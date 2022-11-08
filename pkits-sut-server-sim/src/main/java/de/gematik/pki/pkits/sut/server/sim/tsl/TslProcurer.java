/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.pkits.sut.server.sim.tsl;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.calculateSha256Hex;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier;
import de.gematik.pki.pkits.sut.server.sim.configs.OcspConfig;
import de.gematik.pki.pkits.sut.server.sim.configs.TslConfig;
import de.gematik.pki.pkits.sut.server.sim.configs.TslProcurerConfig;
import de.gematik.pki.pkits.sut.server.sim.exceptions.TosException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.annotation.PreDestroy;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TslProcurer {

  private final TslProcurerConfig tslProcurerConfig;
  private ScheduledExecutorService scheduledExecutorServiceFetchTsl;
  private Tsl theTsl;

  private final OcspConfig ocspConfig;
  private final OcspRespCache ocspRespCache;

  public TslProcurer(final TslProcurerConfig tslProcurerConfig, final OcspConfig ocspConfig) {
    this.tslProcurerConfig = tslProcurerConfig;
    this.ocspConfig = ocspConfig;
    this.ocspRespCache = new OcspRespCache(this.ocspConfig.getOcspGracePeriodSeconds());
    startTslDownloadProcess();
  }

  private static class Tsl {

    final String tslHash;
    final byte[] tslBytes;
    final TrustStatusListType trustStatusListType;

    private final int seqNr;

    public Tsl(final String tslHash, final byte[] tslBytes) {
      this.tslHash = tslHash;
      this.tslBytes = tslBytes;
      trustStatusListType = TslConverter.bytesToTsl(tslBytes).orElseThrow();
      this.seqNr = TslReader.getSequenceNumber(trustStatusListType);
    }
  }

  public TslInformationProvider getTslInfoProv() {
    if (theTsl != null) {
      log.info(
          "Current TSL ID: {}, ({} bytes)",
          theTsl.trustStatusListType.getId(),
          theTsl.tslBytes.length);
      return new TslInformationProvider(TslConverter.bytesToTsl(theTsl.tslBytes).orElseThrow());
    } else {
      throw new TosException("No tsl data available (yet).");
    }
  }

  private void startTslDownloadProcess() {
    scheduledExecutorServiceFetchTsl = Executors.newScheduledThreadPool(1);
    scheduledExecutorServiceFetchTsl.scheduleWithFixedDelay(
        this::processTslDownloadHttpResponse,
        0,
        tslProcurerConfig.getDownloadInterval(),
        TimeUnit.SECONDS);
  }

  private void processTslDownloadHttpResponse() {

    final Optional<HttpResponse<byte[]>> responseDownloadOpt = downloadTslIfRequired();

    if (responseDownloadOpt.isPresent()
        && (responseDownloadOpt.get().getStatus() == HttpStatus.SC_OK)) {

      final byte[] tslBytesRx = responseDownloadOpt.get().getBody();
      log.info("TSL download successful. ({} bytes)", tslBytesRx.length);

      final Tsl rxTsl = new Tsl(calculateSha256Hex(tslBytesRx), tslBytesRx);
      initializeEmptyTrustStore(rxTsl);
      processReceivedTsl(rxTsl);

    } else {
      log.info("Retry TSL download in {} seconds", tslProcurerConfig.getDownloadInterval());
    }
  }

  private Optional<HttpResponse<byte[]>> downloadTslIfRequired() {
    final String url = getUrl();

    try {
      if (theTsl == null) {
        log.info("Downloading initial TSL at: {}", url);
        return Optional.of(Unirest.get(url).asBytes());
      }

      final String hashUrl = makeHashUrl(url);
      final boolean isNewTslAvailable = isNewTslAvailable(theTsl.tslHash, hashUrl);

      if (isNewTslAvailable) {
        log.info("Downloading new TSL at: {}", url);
        return Optional.of(Unirest.get(url).asBytes());
      } else {
        log.info(
            "No TSL download required due to same hash value: {}, url {}", theTsl.tslHash, hashUrl);
      }
    } catch (final UnirestException e) {
      log.info("Downloading TSL failed. {}", e.getMessage());
    }
    return Optional.empty();
  }

  private String getUrl() {
    if (theTsl == null) {
      return TslConfig.buildTslDownloadUrl(tslProcurerConfig.getInitialTslPrimaryDownloadUrl());
    } else {
      return TslReader.getTslDownloadUrlPrimary(theTsl.trustStatusListType);
    }
  }

  private String makeHashUrl(final String tslDownloadUrl) {
    return tslDownloadUrl.replace(".xml", ".sha2");
  }

  private boolean isNewTslAvailable(
      @NonNull final String hashValueLocal, @NonNull final String hashUrl) throws UnirestException {
    final HttpResponse<String> stringHttpResponse = Unirest.get(hashUrl).asString();
    if (stringHttpResponse.getStatus() == HttpStatus.SC_OK) {
      final String hashValueOnline = stringHttpResponse.getBody();
      log.info(
          "Comparing TSL hash: local ({}) vs. online ({}) at: {}",
          hashValueLocal,
          hashValueOnline,
          hashUrl);
      return !hashValueOnline.equals(hashValueLocal);
    } else {
      return false;
    }
  }

  private void processReceivedTsl(@NonNull final Tsl rxTsl) {

    log.info("Downloaded TSL has sequence nr {} and hash {}", rxTsl.seqNr, rxTsl.tslHash);
    final Optional<TucPki001Verifier> tucPki001Verifier = initTucPki001Verifier(rxTsl);
    tucPki001Verifier.ifPresent(
        verifier -> {
          try {
            verifier.performTucPki001Checks();
            updateTruststore(rxTsl);
          } catch (final GemPkiException e) {
            log.info("TUC_PKI_001 failed. TSL rejected.", e);
          } catch (final GemPkiRuntimeException e) {
            // new GemPkiRuntimeException("Keine OCSP Response erhalten.") is thrown
            // when withResponseBytes=false
            log.info("TUC_PKI_001 failed. TSL rejected.");
          } catch (final Exception e) {
            log.info("WARNING: Unexpected exception happened!", e);
            log.info("TUC_PKI_001 failed. TSL rejected.");
          }
        });
  }

  private Optional<TucPki001Verifier> initTucPki001Verifier(@NonNull final Tsl rxTsl) {
    final TrustStatusListType newTslType = rxTsl.trustStatusListType;
    final List<TspService> trustedServices =
        new TslInformationProvider(theTsl.trustStatusListType).getTspServices();
    try {
      return Optional.of(
          TucPki001Verifier.builder()
              .ocspRespCache(ocspRespCache)
              .productType("Test")
              .withOcspCheck(true)
              .tslToCheck(newTslType)
              .currentTrustedServices(trustedServices)
              .ocspTimeoutSeconds(ocspConfig.getOcspTimeoutSeconds())
              .tolerateOcspFailure(ocspConfig.isTolerateOcspFailure())
              .build());
    } catch (final NullPointerException e) {
      log.info("TUC_PKI_001 initialization failed. TSL rejected.", e);
      return Optional.empty();
    }
  }

  /**
   * On startup the truststore is empty. This method sets any TSL as initial truststore.
   *
   * @param initialTsl The initial TSL.
   */
  private void initializeEmptyTrustStore(final Tsl initialTsl) {
    if (theTsl == null) {
      theTsl = initialTsl;
      log.info(
          "Initial TSL with sequence nr {} and hash {} assigned.",
          initialTsl.seqNr,
          initialTsl.tslHash);
    }
  }

  private synchronized void updateTruststore(final Tsl newTsl) {
    theTsl = newTsl;
    log.info("New TSL with sequence nr {} and hash {} assigned.", newTsl.seqNr, newTsl.tslHash);
  }

  @PreDestroy
  private void onExit() {
    log.info("stop all tasks \"downloadTsl\"");
    scheduledExecutorServiceFetchTsl.shutdown();
  }
}
