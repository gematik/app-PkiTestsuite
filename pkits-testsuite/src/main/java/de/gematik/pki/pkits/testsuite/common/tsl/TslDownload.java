/*
 * Copyright 2025, gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.common.tsl;

import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponderException;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestHistoryContainer;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.tsl.provider.api.TslDownloadEndpointType;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderEndpointsConfig;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Builder
public class TslDownload {

  public enum ClearConfigAfterWaiting {
    CLEAR_CONFIG,
    DO_NOT_CLEAR_CONFIG
  }

  @Builder.Default private final int tslDownloadIntervalSeconds = 1;

  @Builder.Default private final int tslProcessingTimeSeconds = 3;
  @Builder.Default private final int ocspProcessingTimeSeconds = 1;

  @Setter private byte @NonNull [] tslBytes;
  @NonNull private final String tslProvUri;
  @NonNull private final String ocspRespUri;

  @NonNull private X509Certificate tslSignerCert;
  @NonNull private X509Certificate trustAnchor;
  @NonNull private final P12Container ocspSigner;
  private final OcspRequestHistoryContainer ocspRequestHistoryContainer =
      new OcspRequestHistoryContainer();

  public TrustStatusListType getTslUnsigned() {
    return TslConverter.bytesToTslUnsigned(tslBytes);
  }

  public void waitUntilTslDownloadCompleted(final int tslSeqNr, final int tslSeqNrFromOcspRequest) {
    configureOcspResponderForTslSigner();
    waitForTslDownload(tslSeqNr);
    waitUntilOcspRequestForTslSigner(tslSeqNrFromOcspRequest);
  }

  public void waitUntilTslDownloadCompletedOptional(final int tslSeqNr) {
    configureOcspResponderForTslSigner();
    waitForTslDownload(tslSeqNr);
    waitUntilOcspRequestForSignerOptional();
  }

  public void configureOcspResponderForTslSigner() {
    try {
      final OcspResponderConfig ocspResponderConfig =
          OcspResponderConfig.builder()
              .certificateDtos(
                  List.of(
                      CertificateDto.builder()
                          .eeCert(tslSignerCert)
                          .issuerCert(trustAnchor)
                          .signer(ocspSigner)
                          .build()))
              .build();

      TestEnvironment.configureOcspResponder(ocspRespUri, ocspResponderConfig);
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  public void configureOcspResponderForTslSigner(final OcspResponderConfig ocspResponderConfig) {
    try {
      TestEnvironment.configureOcspResponder(ocspRespUri, ocspResponderConfig);
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  public void waitForTslDownload(final int expectedTslSeqNr) {
    waitForTslDownload(
        expectedTslSeqNr,
        TslDownloadEndpointType.XML_ENDPOINTS,
        ClearConfigAfterWaiting.CLEAR_CONFIG);
  }

  public void waitForTslDownload(
      final int expectedTslSeqNr,
      final TslDownloadEndpointType tslDownloadEndpointType,
      final ClearConfigAfterWaiting clearConfigAfterWaiting) {

    TestEnvironment.configureTslProvider(
        tslProvUri, tslBytes, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200);
    log.info("Waiting at most {} seconds for TSL download.", tslDownloadIntervalSeconds);
    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for tslSeqNr " + expectedTslSeqNr,
        tslDownloadIntervalSeconds,
        tslDownloadHistoryHasSpecificEntry(tslProvUri, expectedTslSeqNr, tslDownloadEndpointType));

    if (clearConfigAfterWaiting == ClearConfigAfterWaiting.CLEAR_CONFIG) {
      TestEnvironment.clearTslProviderConfig(tslProvUri);
    }
  }

  public static Integer getTslSeqNrOfLastTslDownloadRequest(
      final String tslProvUri, final int tslSeqNr) {
    log.info("Expecting download from TSL with tslSeqNr: {}", tslSeqNr);

    final List<TslRequestHistoryEntryDto> historyEntryDtos =
        TslProviderManager.getTslRequestHistoryPart(
            tslProvUri, tslSeqNr, TslDownloadEndpointType.ANY_ENDPOINT);

    if (historyEntryDtos.isEmpty()) {
      log.info("history for tslSeqNr {} is empty", tslSeqNr);
      return null;
    }

    final int tslSeqNrOfLastTslDownloadHistEntry =
        historyEntryDtos.get(historyEntryDtos.size() - 1).getTslSeqNr();

    log.info("tslSeqNr from last download: {}", tslSeqNrOfLastTslDownloadHistEntry);
    return tslSeqNrOfLastTslDownloadHistEntry;
  }

  public void waitUntilOcspRequestForSignerOptional() {

    try {
      waitUntilOcspRequestForTslSigner();
    } catch (final TestSuiteException e) {
      log.info("no (optional) OCSP requests received -> CONTINUE\n\n");
    }
  }

  public void waitUntilOcspRequestForTslSigner() {
    waitUntilOcspRequestForTslSigner(IGNORE_SEQUENCE_NUMBER);
  }

  public void waitUntilOcspRequestForTslSigner(final int tslSeqNrFromOcspRequest) {
    waitUntilOcspRequestForTslSigner(tslSeqNrFromOcspRequest, ClearConfigAfterWaiting.CLEAR_CONFIG);
  }

  public void waitUntilOcspRequestForTslSigner(
      final int tslSeqNr, final ClearConfigAfterWaiting clearConfigAfterWaiting) {
    final BigInteger tslSignerCertSerialNr = tslSignerCert.getSerialNumber();

    log.info("Waiting {} seconds for ocsp request for tsl signer.", tslProcessingTimeSeconds);
    final long ocsRequestWaitingTimeSeconds =
        PkitsTestSuiteUtils.waitForEvent(
            "OcspRequest received from tsl with sequence nr %s and TSL signer cert %s"
                .formatted(tslSeqNr, tslSignerCertSerialNr),
            tslProcessingTimeSeconds,
            ocspRequestHistoryContainer.ocspRequestHistoryHasEntryForCert(
                ocspRespUri, tslSeqNr, tslSignerCertSerialNr));

    if (clearConfigAfterWaiting == ClearConfigAfterWaiting.CLEAR_CONFIG) {
      TestEnvironment.clearOcspResponderConfig(ocspRespUri);
    }

    log.info(
        "OCSP Request for TSL signer received after {} seconds. Waiting further {} seconds for TSL"
            + " to process",
        ocsRequestWaitingTimeSeconds,
        tslProcessingTimeSeconds - ocsRequestWaitingTimeSeconds);
    PkitsCommonUtils.waitSeconds(tslProcessingTimeSeconds - ocsRequestWaitingTimeSeconds);
    log.info("Waiting for OCSP request in history is over. TSL should be processed now.");
  }

  public static Callable<Boolean> tslDownloadHistoryHasSpecificEntry(
      final String tslProvUri,
      final int tslSeqNr,
      final TslDownloadEndpointType tslDownloadEndpointType) {
    log.debug("Polling TSL download request history, tslSeqNr {}", tslSeqNr);
    return () ->
        !TslProviderManager.getTslRequestHistoryPart(tslProvUri, tslSeqNr, tslDownloadEndpointType)
            .isEmpty();
  }
}
