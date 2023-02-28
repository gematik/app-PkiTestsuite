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

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static de.gematik.pki.pkits.common.PkitsConstants.VALID_ISSUER_CERT_TSL_CA8;
import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_DEFAULT_USECASE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_VALID;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.common.tsl.TslDownload.tslDownloadHistoryHasSpecificEntry;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslValidator;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

@Slf4j
@DisplayName("PKI TSL approval tests.")
@Order(1)
class TslApprovalTestsIT extends ApprovalTestsBaseIT {

  public static final Path alternativeCaRevokedPretty =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altCA_revoked_pretty.xml");

  private void verifyUpdateTrustStoreInTestObject_initialStateWithAlternativeCert()
      throws DatatypeConfigurationException, IOException {

    log.info("verifyUpdateTrustStoreInTestObject: initialStateWithAlternativeCert");

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  private void verifyUpdateTrustStoreInTestObject1_AlternativeCaRevoked()
      throws DatatypeConfigurationException, IOException {

    log.info("verifyUpdateTrustStoreInTestObject: case 1 - AlternativeCaRevoked");
    final Path tslTemplatePath = tslSettings.getAlternativeRevokedTemplate();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadWithTemplate(offeredSeqNr, tslTemplatePath);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(offeredSeqNr);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  private void verifyUpdateTrustStoreInTestObject2_AlternativeCaNoLineBreaks()
      throws DatatypeConfigurationException, IOException {
    log.info("verifyUpdateTrustStoreInTestObject: case 2 - AlternativeCaNoLineBreaks");
    final Path tslTemplatePath =
        testSuiteConfig
            .getTestSuiteParameter()
            .getTslSettings()
            .getAlternativeNoLineBreakTemplate();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadWithTemplate(offeredSeqNr, tslTemplatePath);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(offeredSeqNr);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  private void verifyUpdateTrustStoreInTestObject3_Default()
      throws DatatypeConfigurationException, IOException {
    log.info("verifyUpdateTrustStoreInTestObject: case 3 - Default");
    final Path tslTemplatePath =
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getDefaultTemplate();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadWithTemplate(offeredSeqNr, tslTemplatePath);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(offeredSeqNr);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_001 */
  @Test
  @Afo(afoId = "GS-A_4649", description = "TUC_PKI_020: XML-Dokument validieren")
  @DisplayName("Test update of TSL with different XML format (pretty print)")
  @Disabled("Correct Testcase with PrettyPrint TSL (PKITS-158 and GLP-263)")
  void verifyUpdateTrustStoreInTestObject(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);

    verifyUpdateTrustStoreInTestObject_initialStateWithAlternativeCert();

    verifyUpdateTrustStoreInTestObject1_AlternativeCaRevoked();
    verifyUpdateTrustStoreInTestObject2_AlternativeCaNoLineBreaks();
    verifyUpdateTrustStoreInTestObject3_Default();
  }

  /** gematikId: UE_PKI_TC_0104_004 */
  @Test
  @Afo(
      afoId = "TIP1-A_5120",
      description = "Clients des TSL-Dienstes: HTTP-Komprimierung unterstützen")
  @DisplayName("Test compression of TSL download")
  void verifyTslDownloadCompression(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getCurrentNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds() + 5,
        tslDownloadHistoryHasSpecificEntry(tslProvUri, tslSequenceNr.getCurrentNrInTestObject()));

    final List<TslRequestHistoryEntryDto> historyEntryDtos =
        TslProviderManager.getTslRequestHistoryPart(
            tslProvUri, tslSequenceNr.getExpectedNrInTestObject());

    assertThat(historyEntryDtos).as("No TSL download requests received").isNotEmpty();

    final TslRequestHistoryEntryDto historyEntryDto =
        historyEntryDtos.get(historyEntryDtos.size() - 1);

    assertThat(historyEntryDto.isGzipCompressed())
        .as("TSL download requests has to contain accept-encoding: gzip")
        .isTrue();
    assertThat(historyEntryDto.getProtocol())
        .as("TSL download requests has to be with http version 1.1")
        .isEqualTo("HTTP/1.1");
  }

  /** gematikId: UE_PKI_TC_0103_004 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 6")
  @DisplayName("Test TSL service does not provide updated TSL")
  void verifyIrregularDifferencesBetweenCurrentAndNewTsls(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final TslDownload initialTslDownload = initialTslDownloadByTestObject();

    {
      log.info("case 0: same tsl");

      // brauch man nicht unbedingt, da sich nichts ändert
      // tslSequenceNr.setLastOfferedNr(TslReader.getSequenceNumber(initialTslDownload.getTsl()).intValue());
      initialTslDownload.waitUntilOptionalTslDownloadCompleted(
          tslSequenceNr.getExpectedNrInTestObject());

      final Path certPath = getPathOfFirstValidCert();
      useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
    }

    {
      log.info("case 1: new seqNr is smaller");
      final int offeredSeqNr = tslSequenceNr.getCurrentNrInTestObject() - 1;
      log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
      final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

      tslSequenceNr.setLastOfferedNr(offeredSeqNr);
      tslDownload.waitUntilOptionalTslDownloadCompleted(tslSequenceNr.getExpectedNrInTestObject());

      final Path certPath = getPathOfAlternativeCertificate();
      useCaseWithCert(
          certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
    }

    {
      log.info("case 2: different tsl ids, but same seqNr");
      final int offeredSeqNr = tslSequenceNr.getCurrentNrInTestObject();
      log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
      final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

      tslSequenceNr.setLastOfferedNr(offeredSeqNr);
      tslDownload.waitUntilOptionalTslDownloadCompleted(tslSequenceNr.getExpectedNrInTestObject());

      final Path certPath = getPathOfAlternativeCertificate();
      useCaseWithCert(
          certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
    }

    {
      log.info("case 3: same tsl ids, but new seqNr is higher");
      log.info(
          "initial tsl seqNr: {}, id: {}",
          initialTslDownload.getTsl().getId(),
          initialTslDownload.getTsl().getSchemeInformation().getTSLSequenceNumber());
      final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
      log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

      final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

      final byte[] tslBytes = tslDownload.getTslBytes();

      final String newId = initialTslDownload.getTsl().getId();
      final byte[] tslBytesWithNewId = TslModifier.modifiedTslId(tslBytes, newId);

      signAndSetTslBytes(tslDownload, tslSigner, tslBytesWithNewId);
      writeTsl(tslDownload, "_modified");

      tslSequenceNr.setLastOfferedNr(offeredSeqNr);
      tslDownload.waitUntilOptionalTslDownloadCompleted(tslSequenceNr.getExpectedNrInTestObject());

      final Path certPath = getPathOfAlternativeCertificate();
      useCaseWithCert(
          certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
    }
  }

  /** gematikId: UE_PKI_TC_0102_004 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 6")
  @DisplayName("Test bad CA certificate is not extractable from TSL")
  void verifyForBadCertificateOfTSPService(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    bringInTslDownload(
        tslSettings.getDefectAlternativeCaBrokenTemplate(),
        tslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_005 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 6")
  @DisplayName("Test proper handling of unspecified CA certificate in TSL")
  void verifyForUnspecifiedCertificateOfTSPService(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    bringInTslDownload(
        tslSettings.getDefectAlternativeCaUnspecifiedTemplate(),
        tslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_006 */
  @Test
  @Afo(afoId = "GS-A_4749", description = "TUC_PKI_007: Prüfung Zertifikatstyp - Schritt 8")
  @DisplayName("Test CA certificate with missing service information extension in TSL")
  void verifyForWrongServiceInfoExtCertificateOfTSPService(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    bringInTslDownload(
        tslSettings.getDefectAlternativeCaWrongSrvInfoExtTemplate(),
        tslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID,
        OCSP_REQUEST_IGNORE);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_007 */
  @Test
  @Afo(afoId = "A_17700", description = "TSL-Auswertung ServiceTypeIdentifier \"unspecified\"")
  @DisplayName("Test CA certificate with ServiceTypeIdentifier \"unspecified\" in TSL")
  void verifyForUnspecifiedServiceTypeIdentifierOfTSPService(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    bringInTslDownload(
        tslSettings.getAlternativeCaUnspecifiedStiTemplate(),
        tslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_037 */
  @Test
  @Afo(afoId = "GS-A_4652", description = "TUC_PKI_018: Zertifikatsprüfung in der TI - Schritt 5a")
  @DisplayName("Test CA certificate in TSL is revoked and EE certificate is issued later.")
  void verifyRevokedCaCertificateInTslLater(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    waitForOcspCacheToExpire();

    bringInTslDownload(
        alternativeCaRevokedPretty,
        tslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_038 */
  @Test
  @Afo(afoId = "GS-A_4652", description = "TUC_PKI_018: Zertifikatsprüfung in der TI - Schritt 5")
  @DisplayName("Test CA certificate in TSL is revoked and EE certificate is issued earlier.")
  void verifyRevokedCaCertificateInTsl(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    waitForOcspCacheToExpire();

    final Path tslTemplatePath = Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altCA_revokedLater.xml");

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

    final TslDownload tslDownload = getTslDownloadWithTemplate(offeredSeqNr, tslTemplatePath);

    final ZonedDateTime newStatusStartingTime = GemLibPkiUtils.now().plusDays(1);

    final byte[] tslBytes = tslDownload.getTslBytes();
    final byte[] tslBytesWithNewStatusStartingTime =
        TslModifier.modifiedStatusStartingTime(
            tslBytes,
            PkitsConstants.GEMATIK_TEST_TSP,
            null,
            TslConstants.SVCSTATUS_REVOKED,
            newStatusStartingTime);

    signAndSetTslBytes(tslDownload, tslSigner, tslBytesWithNewStatusStartingTime);
    writeTsl(tslDownload, "_modified");

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_009 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "Prüfung der Aktualität der TSL - Schritt 4")
  @Afo(afoId = "GS-GS-A_4651", description = "TUC_PKI_012: XML-Signatur-Prüfung")
  @DisplayName("Test TSL signature invalid - \"to be signed block\" with integrity violation")
  void verifyTslSignatureInvalid(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

    // create TSL and verify signature
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);
    assertThat(TslValidator.checkSignature(tslDownload.getTslBytes(), VALID_ISSUER_CERT_TSL_CA8))
        .isTrue();

    // break integrity of TSL and verify signature again
    final String mailToStrOld = getFirstSchemeOperatorMailAddressOfTsl(tslDownload.getTslBytes());
    final String mailToStrNew = "mailto:signatureInvalid@gematik.de";
    final String tslStr = new String(tslDownload.getTslBytes(), StandardCharsets.UTF_8);
    final byte[] brokenTsl =
        tslStr.replace(mailToStrOld, mailToStrNew).getBytes(StandardCharsets.UTF_8);

    tslDownload.setTslBytes(brokenTsl);
    writeTsl(tslDownload, "_modified");

    log.info("Verify test tsl has wrong signature.");
    assertThat(TslValidator.checkSignature(tslDownload.getTslBytes(), VALID_ISSUER_CERT_TSL_CA8))
        .isFalse();

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilOptionalTslDownloadCompleted(tslSequenceNr.getExpectedNrInTestObject());

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_IGNORE);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  private String getFirstSchemeOperatorMailAddressOfTsl(final byte[] tslBytes) {
    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);
    return tsl.getSchemeInformation()
        .getSchemeOperatorAddress()
        .getElectronicAddress()
        .getURI()
        .get(0)
        .getValue();
  }

  /** gematikId: UE_PKI_TC_0104_001 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3 und 4")
  @DisplayName("Test TSL download not possible")
  void verifyRetryFailingTslDownload(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    waitForOcspCacheToExpire();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();

    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    log.info(
        "wait until next TSL download for CURRENT seqNr {} is over",
        tslSequenceNr.getCurrentNrInTestObject());
    PkitsTestSuiteUtils.waitForEventMillis(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getCurrentNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds(),
        100,
        TslDownload.tslDownloadHistoryHasSpecificEntry(
            tslProvUri, tslSequenceNr.getCurrentNrInTestObject()));

    TslProviderManager.clearTslHistory(tslProvUri);

    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    tslDownload.configureOcspResponderTslSignerStatusGood();

    log.info("configure TslProvider to return error 404");
    TestEnvironment.configureTslProvider(
        tslProvUri,
        tslDownload.getTslBytes(),
        TSL_DOWNLOAD_POINT_PRIMARY,
        TslProviderEndpointsConfig.PRIMARY_404_BACKUP_404);

    final Callable<Boolean> callable =
        () -> {
          final List<TslRequestHistoryEntryDto> tslRequestHistoryEntryDtos =
              TslProviderManager.getTslRequestHistoryPart(
                  tslProvUri, tslSequenceNr.getExpectedNrInTestObject());

          final long primaryTslCount =
              tslRequestHistoryEntryDtos.stream()
                  .filter(dto -> dto.getTslDownloadEndpoint().contains(TSL_XML_PRIMARY_ENDPOINT))
                  .count();

          final long backupTslCount =
              tslRequestHistoryEntryDtos.stream()
                  .filter(dto -> dto.getTslDownloadEndpoint().contains(TSL_XML_BACKUP_ENDPOINT))
                  .count();

          log.info(
              "current tslRequestHistoryEntryDtos:\n  {}",
              tslRequestHistoryEntryDtos.stream()
                  .map(TslRequestHistoryEntryDto::toString)
                  .collect(Collectors.joining("\n  ")));

          final int maxEndpointRepetitions = 4;

          final boolean b1 = (primaryTslCount == maxEndpointRepetitions);
          final boolean b2 = (backupTslCount == maxEndpointRepetitions);

          log.info("primaryTslCount: {}, backupTslCount  {}", primaryTslCount, backupTslCount);

          return b1 && b2;
        };

    PkitsTestSuiteUtils.waitForEventMillis(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getExpectedNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds(),
        100,
        callable);

    assertNoOcspRequest(tslDownload);

    // TODO clarify if really need it
    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(offeredSeqNr);

    // TODO clarify if need it
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0104_002 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3 und 4")
  @DisplayName("Test TSL download on primary endpoint not possible")
  void verifyUseBackupTslDownload(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    waitForOcspCacheToExpire();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();

    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    log.info(
        "wait until next TSL download for CURRENT seqNr {} is over",
        tslSequenceNr.getCurrentNrInTestObject());
    PkitsTestSuiteUtils.waitForEventMillis(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getCurrentNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds(),
        100,
        TslDownload.tslDownloadHistoryHasSpecificEntry(
            tslProvUri, tslSequenceNr.getCurrentNrInTestObject()));

    TslProviderManager.clearTslHistory(tslProvUri);

    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    tslDownload.configureOcspResponderTslSignerStatusGood();

    log.info("configure TslProvider to return error 404 on primary endpoint, and 200 on backup");
    TestEnvironment.configureTslProvider(
        tslProvUri,
        tslDownload.getTslBytes(),
        TSL_DOWNLOAD_POINT_PRIMARY,
        TslProviderEndpointsConfig.PRIMARY_404_BACKUP_200);

    final Callable<Boolean> callable =
        () -> {
          final List<TslRequestHistoryEntryDto> tslRequestHistoryEntryDtos =
              TslProviderManager.getTslRequestHistoryPart(
                  tslProvUri, tslSequenceNr.getExpectedNrInTestObject());

          final long primaryTslCount =
              tslRequestHistoryEntryDtos.stream()
                  .filter(dto -> dto.getTslDownloadEndpoint().contains(TSL_XML_PRIMARY_ENDPOINT))
                  .count();

          final long backupTslCount =
              tslRequestHistoryEntryDtos.stream()
                  .filter(dto -> dto.getTslDownloadEndpoint().contains(TSL_XML_BACKUP_ENDPOINT))
                  .count();

          log.info(
              "current tslRequestHistoryEntryDtos:\n  {}",
              tslRequestHistoryEntryDtos.stream()
                  .map(TslRequestHistoryEntryDto::toString)
                  .collect(Collectors.joining("\n  ")));

          final int maxEndpointRepetitions = 4;

          final boolean b1 = (primaryTslCount == maxEndpointRepetitions);
          final boolean b2 = (backupTslCount == 1);

          log.info("primaryTslCount: {}, backupTslCount  {}", primaryTslCount, backupTslCount);

          return b1 && b2;
        };

    PkitsTestSuiteUtils.waitForEventMillis(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getExpectedNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds(),
        100,
        callable);

    tslDownload.waitUntilOcspRequestForSigner();

    // TODO clarify if really need it
    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(offeredSeqNr);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }
}
