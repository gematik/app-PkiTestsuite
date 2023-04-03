/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.common.tsl;

import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponderException;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.config.OcspSettings;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
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

  private static final TestSuiteConfig testSuiteConfig = TestConfigManager.getTestSuiteConfig();

  private static final OcspSettings ocspSettings =
      testSuiteConfig.getTestSuiteParameter().getOcspSettings();

  private static final P12Container ocspSigner =
      P12Reader.getContentFromP12(
          ocspSettings.getKeystorePathOcsp().resolve(TestSuiteConstants.OCSP_SIGNER_FILENAME),
          ocspSettings.getSignerPassword());

  @Builder.Default private final int tslDownloadIntervalSeconds = 1;

  @Builder.Default private final int tslProcessingTimeSeconds = 3;

  @Setter private byte @NonNull [] tslBytes;
  @NonNull private final String tslProvUri;
  @NonNull private final String ocspRespUri;

  @NonNull private final TslDownloadPoint tslDownloadPoint;
  @NonNull private X509Certificate tslSignerCert;

  private List<OcspRequestHistoryEntryDto> lastOcspRequestHistoryEntries;

  public TrustStatusListType getTsl() {
    return TslConverter.bytesToTsl(tslBytes);
  }

  public void waitUntilTslDownloadCompleted(final int sequenceNr, final int ocspSeqNr) {
    configureOcspResponderTslSignerStatusGood();
    waitForTslDownload(sequenceNr);
    waitUntilOcspRequestForSigner(ocspSeqNr);
  }

  public void waitUntilTslDownloadCompletedOptional(final int sequenceNr) {
    configureOcspResponderTslSignerStatusGood();
    waitForTslDownload(sequenceNr);
    waitUntilOcspRequestForSignerOptional();
  }

  public void configureOcspResponderTslSignerStatusGood() {
    try {
      final OcspResponderConfigDto dto =
          OcspResponderConfigDto.builder().eeCert(tslSignerCert).signer(ocspSigner).build();

      TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  public void configureOcspResponderTslSignerStatusGood(
      final OcspResponderConfigDto.OcspResponderConfigDtoBuilder builder) {
    try {
      TestEnvironment.configureOcspResponder(ocspRespUri, builder.build());
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  public void waitForTslDownload(final int expectedSeqNr) {

    TestEnvironment.configureTslProvider(
        tslProvUri, tslBytes, tslDownloadPoint, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200);
    log.info("Waiting at most {} seconds for TSL download.", tslDownloadIntervalSeconds);
    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for seqNr " + expectedSeqNr,
        tslDownloadIntervalSeconds,
        tslDownloadHistoryHasSpecificEntry(tslProvUri, expectedSeqNr));
    TestEnvironment.clearTslProviderConfig(tslProvUri);
  }

  public static Integer getSeqNrOfLastTslDownload(final String tslProvUri, final int sequenceNr) {
    log.info("Expecting download from TSL with seqNr.: {}", sequenceNr);

    final List<TslRequestHistoryEntryDto> historyEntryDtos =
        TslProviderManager.getTslRequestHistoryPart(tslProvUri, sequenceNr);

    if (historyEntryDtos.isEmpty()) {
      log.info("history for seqNr {} is empty", sequenceNr);
      return null;
    }

    final int seqNrOfLastTslDownloadHistEntry =
        historyEntryDtos.get(historyEntryDtos.size() - 1).getSequenceNr();

    log.info("Last know TSL seqNr in history: {}", seqNrOfLastTslDownloadHistEntry);
    return seqNrOfLastTslDownloadHistEntry;
  }

  public void waitUntilOcspRequestForSignerOptional() {

    try {
      waitUntilOcspRequestForSigner();
    } catch (final TestSuiteException e) {
      log.info("no ocsp optional requests received -> continue\n\n");
    }
  }

  public void waitUntilOcspRequestForSigner() {
    waitUntilOcspRequestForSigner(IGNORE_SEQUENCE_NUMBER);
  }

  public void waitUntilOcspRequestForSigner(final int seqNr) {
    final BigInteger tslSignerCertSerialNr = tslSignerCert.getSerialNumber();
    final long ocsRequestWaitingTimeSeconds =
        PkitsTestSuiteUtils.waitForEvent(
            "OcspRequestHistoryHasEntry for seqNr %s and TSL signer cert %s"
                .formatted(seqNr, tslSignerCertSerialNr),
            tslProcessingTimeSeconds,
            ocspRequestHistoryHasEntryForCert(seqNr, tslSignerCertSerialNr));

    TestEnvironment.clearOcspResponderConfig(ocspRespUri);

    // TODO run in thread coupled to waitForOcspCacheToExpire() from a UseCaseExecution
    log.info(
        "OCSP Request for TSL signer received after {} seconds. Waiting further {} seconds for TSL"
            + " to process",
        ocsRequestWaitingTimeSeconds,
        tslProcessingTimeSeconds - ocsRequestWaitingTimeSeconds);
    PkitsCommonUtils.waitSeconds(tslProcessingTimeSeconds - ocsRequestWaitingTimeSeconds);
    log.info("Waiting for OCSP request in history is over. TSL should be processed now.");
  }

  public static Callable<Boolean> tslDownloadHistoryHasSpecificEntry(
      final String tslProvUri, final int sequenceNr) {
    log.debug("Polling TSL download request history, seqNr {}", sequenceNr);
    return () -> !TslProviderManager.getTslRequestHistoryPart(tslProvUri, sequenceNr).isEmpty();
  }

  private Callable<Boolean> ocspRequestHistoryHasEntryForCert(
      final int seqNr, final BigInteger certSerial) {
    log.debug("Polling TSL download request history");
    return () -> {
      lastOcspRequestHistoryEntries =
          OcspResponderManager.getOcspHistoryPart(ocspRespUri, seqNr, certSerial);
      return !lastOcspRequestHistoryEntries.isEmpty();
    };
  }
}
