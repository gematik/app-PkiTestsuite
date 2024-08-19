/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.pkits.sut.server.sim.tsl;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.calculateSha256Hex;
import static de.gematik.pki.pkits.sut.server.sim.PkiSutServerSimApplication.PRODUCT_TYPE;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TslUtils;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier.TrustAnchorUpdate;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.sut.server.sim.PkiSutServerSimApplication;
import de.gematik.pki.pkits.sut.server.sim.configs.OcspConfig;
import de.gematik.pki.pkits.sut.server.sim.configs.TslConfig;
import de.gematik.pki.pkits.sut.server.sim.configs.TslProcurerConfig;
import de.gematik.pki.pkits.sut.server.sim.exceptions.TosException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import jakarta.annotation.PreDestroy;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TslProcurer {

  private static final String TUC_PKI_001_FAILED = "TUC_PKI_001 failed. TSL rejected.";
  private final TslProcurerConfig tslProcurerConfig;
  private ScheduledExecutorService scheduledExecutorServiceFetchTsl;

  private boolean isInitialized = false;
  private Tsl currentTsl = null;
  private TspService tspServiceTrustAnchor = null;

  private final StatefulTrustAnchorUpdate statefulTrustAnchorUpdate =
      new StatefulTrustAnchorUpdate();
  private final OcspConfig ocspConfig;
  private final OcspRespCache ocspRespCache;

  public TslProcurer(final TslProcurerConfig tslProcurerConfig, final OcspConfig ocspConfig) {
    this.tslProcurerConfig = tslProcurerConfig;
    this.ocspConfig = ocspConfig;
    this.ocspRespCache = new OcspRespCache(this.ocspConfig.getOcspGracePeriodSeconds());
    startTslDownloadProcess();
  }

  public TslInformationProvider getTslInfoProv() {
    if (currentTsl != null) {
      log.info(
          "Current TSL ID: {}, ({} bytes)",
          currentTsl.tslUnsigned.getId(),
          currentTsl.tslBytes.length);
      return new TslInformationProvider(TslConverter.bytesToTslUnsigned(currentTsl.tslBytes));
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

    if (isInitialized && !hasValidTrustStore()) {
      log.error(
          "Test Object does not have a valid trust store anymore. New TSL must be manually"
              + " imported!");
      return;
    }

    try {
      log.info("Starting new TSL download interval!");
      final Optional<TslDownloadResults> tslDownloadResultsOpt = downloadTslIfHashIsDifferent();

      if (tslDownloadResultsOpt.isPresent() && !tslDownloadResultsOpt.get().failed) {

        final byte[] rxTslBytes = tslDownloadResultsOpt.get().tslBytes;
        log.info("TSL download successful. ({} bytes)", rxTslBytes.length);

        final String rxTslHash = calculateSha256Hex(rxTslBytes);

        initializeEmptyTrustStore(rxTslHash, rxTslBytes);
        processReceivedTsl(rxTslHash, rxTslBytes);

        log.info("TSL download interval finished!");
      } else {
        log.info("Retry TSL download in {} seconds", tslProcurerConfig.getDownloadInterval());
      }
    } catch (final Exception e) {
      log.error("something is wrong - cannot process tsl", e);
    }
  }

  private TslDownloadResults downloadTsl(final String tslUrl, final String additionalInfo) {
    log.info("{}: downloading TSL at: {}", additionalInfo, tslUrl);
    try {
      Unirest.config().reset().connectTimeout(tslProcurerConfig.getTimeoutMilliseconds());
      final HttpResponse<byte[]> bytesResponse = Unirest.get(tslUrl).asBytes();
      return TslDownloadResults.forTslBytes(bytesResponse);
    } catch (final UnirestException e) {
      log.info("Downloading TSL failed. {}", e.getMessage());
    }

    return TslDownloadResults.fail();
  }

  private boolean hasSameHash(
      final Optional<String> tslPrimaryUrl, final Optional<String> tslBackupUrl) {
    final Optional<String> hashPrimaryUrl = makeHashUrl(tslPrimaryUrl);
    final Optional<String> hashBackupUrl = makeHashUrl(tslBackupUrl);

    TslDownloadResults hashTslDownloadResults =
        hashPrimaryUrl.isPresent()
            ? downloadTslHash(hashPrimaryUrl.get())
            : TslDownloadResults.fail();

    if (hashTslDownloadResults.failed) {
      hashTslDownloadResults =
          hashBackupUrl.isPresent()
              ? downloadTslHash(hashBackupUrl.get())
              : TslDownloadResults.fail();
    }

    if (hashTslDownloadResults.failed) {
      return false;
    }

    return hasSameTslHash(currentTsl.tslHash, hashTslDownloadResults.hashValue);
  }

  private void invalidateTrustStore() {
    tspServiceTrustAnchor = null;
    currentTsl = null;
  }

  private boolean hasValidTrustStore() {
    return ObjectUtils.allNotNull(tspServiceTrustAnchor, currentTsl);
  }

  private Optional<TslDownloadResults> downloadTslIfHashIsDifferent() {

    if (!isInitialized) {
      final String tslInitialUrl = getInitialTslUrl();
      final TslDownloadResults tslDownloadResults = downloadTsl(tslInitialUrl, "Initial TSL");
      return Optional.of(tslDownloadResults);
    }

    final Optional<String> tslPrimaryUrl = getPrimaryTslUrl();

    final Optional<String> tslBackupUrl = getTslBackupUrl();

    if (hasSameHash(tslPrimaryUrl, tslBackupUrl)) {
      log.info(
          "No TSL download required, since hash value was not changed - {}  (current tslSeqNr {})",
          currentTsl.tslHash,
          currentTsl.tslSeqNr);

      verifyTslValidity();

      return Optional.empty();
    }

    for (int i = 0; i < 8; ++i) {

      final Optional<String> urlToUseOpt;
      final String urlType;
      if (i < 4) {
        urlToUseOpt = tslPrimaryUrl;
        urlType = "Primary";
      } else {
        urlToUseOpt = tslBackupUrl;
        urlType = "Backup ";
      }

      final TslDownloadResults tslDownloadResults;
      if (urlToUseOpt.isPresent()) {
        tslDownloadResults =
            downloadTsl(urlToUseOpt.get(), "%s, attempt count=%d.".formatted(urlType, i + 1));
      } else {
        log.info("{}, attempt count={} is SKIPPED as the URL is undefined.", urlType, (i + 1));
        tslDownloadResults = TslDownloadResults.fail();
      }

      if (!tslDownloadResults.failed) {
        log.info("Successful TSL download after {} attempts.", i + 1);

        if (Arrays.equals(tslDownloadResults.tslBytes, currentTsl.tslBytes)) {
          verifyTslValidity();
        }
        return Optional.of(tslDownloadResults);
      }
    }

    log.error(
        ErrorCode.TE_1006_TSL_DOWNLOAD_ERROR.getErrorMessage(
            PkiSutServerSimApplication.PRODUCT_TYPE));
    return Optional.empty();
  }

  private void verifyTslValidity() {
    try {
      TucPki001Verifier.verifyTslValidity(
          GemLibPkiUtils.now(),
          tslProcurerConfig.getTslGracePeriodDays(),
          currentTsl.tslUnsigned,
          PRODUCT_TYPE);
    } catch (final GemPkiException e) {
      invalidateTrustStore();
      log.error("TSL is not valid anymore; Trust Store was cleared.");
      throw new TosException(e.getMessage());
    }
  }

  private String getInitialTslUrl() {
    return TslConfig.buildTslDownloadUrl(tslProcurerConfig.getInitialTslPrimaryDownloadUrl());
  }

  private Optional<String> getPrimaryTslUrl() {
    try {
      return Optional.of(TslReader.getTslDownloadUrlPrimary(currentTsl.tslUnsigned));
    } catch (final GemPkiRuntimeException e) {
      log.warn("cannot extract primary tsl url: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private Optional<String> getTslBackupUrl() {

    try {
      return Optional.of(TslReader.getTslDownloadUrlBackup(currentTsl.tslUnsigned));

    } catch (final GemPkiRuntimeException e) {
      log.warn("cannot extract backup tsl url: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private Optional<String> makeHashUrl(final Optional<String> tslDownloadUrl) {
    return tslDownloadUrl.map(s -> s.replace(".xml", ".sha2"));
  }

  private TslDownloadResults downloadTslHash(@NonNull final String hashUrl) {

    try {
      Unirest.config().reset().connectTimeout(tslProcurerConfig.getTimeoutMilliseconds());
      final HttpResponse<String> stringHttpResponse = Unirest.get(hashUrl).asString();
      return TslDownloadResults.forHash(stringHttpResponse);
    } catch (final UnirestException e) {
      log.info("Downloading TSL HASH failed. {}", e.getMessage());
    }

    return TslDownloadResults.fail();
  }

  private boolean hasSameTslHash(
      @NonNull final String hashValueLocal, @NonNull final String hashValueOnline)
      throws UnirestException {
    log.info("Comparing TSL hash: local ({}) vs. online ({})", hashValueLocal, hashValueOnline);
    return hashValueOnline.equals(hashValueLocal);
  }

  private void processReceivedTsl(
      @NonNull final String rxTslHash, final byte @NonNull [] rxTslBytes) {

    log.info(
        "before processReceivedTsl - current tsl TSL ID: {}, ({} bytes)",
        currentTsl.tslUnsigned.getId(),
        currentTsl.tslBytes.length);

    log.info("Downloaded TSL has hash {}", rxTslHash);

    tspServiceTrustAnchor =
        statefulTrustAnchorUpdate.getFutureTspServiceTrustAnchorOrCurrent(tspServiceTrustAnchor);

    final Optional<TucPki001Verifier> tucPki001VerifierOpt =
        initTucPki001Verifier(rxTslBytes, tspServiceTrustAnchor);

    if (tucPki001VerifierOpt.isEmpty()) {
      log.info("tucPki001VerifierOpt.isEmpty()");
      return;
    }

    try {
      final byte[] certBytes =
          tspServiceTrustAnchor
              .getTspServiceType()
              .getServiceInformation()
              .getServiceDigitalIdentity()
              .getDigitalId()
              .get(0)
              .getX509Certificate();

      final X509Certificate cert = CertReader.readX509(certBytes);

      log.info(
          "current trust anchor: certSerialNr {}, subjectName {}",
          cert.getSerialNumber(),
          cert.getSubjectX500Principal().getName());

      log.info("tucPki001VerifierOpt.get().performTucPki001Checks()");
      final Optional<TrustAnchorUpdate> newTrustAnchorUpdateOpt =
          tucPki001VerifierOpt.get().performTucPki001Checks();

      final Tsl rxTsl = new Tsl(rxTslHash, rxTslBytes);

      statefulTrustAnchorUpdate.updateTrustAnchorIfNecessary(rxTsl, newTrustAnchorUpdateOpt);

      updateTruststore(rxTsl);
    } catch (final GemPkiException e) {
      log.info(TUC_PKI_001_FAILED, e);
    } catch (final GemPkiRuntimeException e) {
      // new GemPkiRuntimeException("Keine OCSP Response erhalten.") is thrown
      // when withResponseBytes=false
      log.info(TUC_PKI_001_FAILED, e);
    } catch (final Exception e) {
      log.info("WARNING: Unexpected exception happened!", e);
      log.info(TUC_PKI_001_FAILED);
    }

    statefulTrustAnchorUpdate.reset();

    if (currentTsl != null) {
      log.info(
          "current tsl TSL ID: {}, ({} bytes)",
          currentTsl.tslUnsigned.getId(),
          currentTsl.tslBytes.length);
    }
  }

  private Optional<TucPki001Verifier> initTucPki001Verifier(
      final byte @NonNull [] rxTslBytes, final TspService tspServiceTrustAnchor) {

    final String currentTslId = currentTsl.tslUnsigned.getId();
    final BigInteger currentTslSeqNr =
        currentTsl.tslUnsigned.getSchemeInformation().getTSLSequenceNumber();

    final List<TspService> tspServices = new ArrayList<>();
    tspServices.add(tspServiceTrustAnchor);

    final TslInformationProvider tslInformationProvider =
        new TslInformationProvider(currentTsl.tslUnsigned);
    final List<TspService> tspServicesFiltered =
        tslInformationProvider.getFilteredTspServices(List.of(TslConstants.STI_OCSP));

    tspServices.addAll(tspServicesFiltered);

    try {
      log.info("build TucPki001Verifier");

      final TucPki001Verifier tucPki001Verifier =
          TucPki001Verifier.builder()
              .ocspRespCache(ocspRespCache)
              .productType(PRODUCT_TYPE)
              .withOcspCheck(true)
              .tslToCheck(rxTslBytes)
              .currentTrustedServices(tspServices)
              .currentTslId(currentTslId)
              .currentTslSeqNr(currentTslSeqNr)
              .ocspTimeoutSeconds(ocspConfig.getOcspTimeoutSeconds())
              .tolerateOcspFailure(ocspConfig.isTolerateOcspFailure())
              .build();

      return Optional.of(tucPki001Verifier);
    } catch (final NullPointerException e) {
      log.info("TUC_PKI_001 initialization failed. TSL rejected.", e);
      return Optional.empty();
    }
  }

  static TspService getIssuerTspServiceForTslSigner(final TrustStatusListType tsl) {
    final TslInformationProvider tslIp = new TslInformationProvider(tsl);

    final TspInformationProvider tspIp =
        new TspInformationProvider(tslIp.getTspServices(), PRODUCT_TYPE);

    try {
      return tspIp.getIssuerTspService(TslUtils.getFirstTslSignerCertificate(tsl));
    } catch (final GemPkiException e) {
      final String message =
          "Error finding trust anchor in TSL information: "
              + e.getError().getErrorMessage(PkiSutServerSimApplication.PRODUCT_TYPE);
      throw new TosException(message);
    }
  }

  /**
   * On startup the truststore is empty. This method sets any TSL as initial truststore.
   *
   * @param tslHash hash of the initial TSL
   * @param tslBytes content of the initial TSL
   */
  private void initializeEmptyTrustStore(final String tslHash, final byte[] tslBytes) {
    if (isInitialized) {
      return;
    }

    currentTsl = new Tsl(tslHash, tslBytes);
    tspServiceTrustAnchor = getIssuerTspServiceForTslSigner(currentTsl.tslUnsigned);
    isInitialized = true;

    log.info(
        "Initial TSL with tslSeqNr {} and hash {} assigned.",
        currentTsl.tslSeqNr,
        currentTsl.tslHash);
  }

  private synchronized void updateTruststore(final Tsl newTsl) {
    currentTsl = newTsl;
    // in fact, we should handle the trust anchor separately and not as a typical CA cert
    tspServiceTrustAnchor = getIssuerTspServiceForTslSigner(currentTsl.tslUnsigned);
    log.info("New TSL with tslSeqNr {} and hash {} assigned.", newTsl.tslSeqNr, newTsl.tslHash);
  }

  @PreDestroy
  private void onExit() {
    log.info("stop all tasks \"downloadTsl\"");
    scheduledExecutorServiceFetchTsl.shutdown();
  }
}
