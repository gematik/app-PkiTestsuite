/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.common.tsl.TslDownload.tslDownloadHistoryHasSpecificEntry;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslConverter.DocToBytesOption;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslSigner;
import de.gematik.pki.gemlibpki.tsl.TslUtils;
import de.gematik.pki.gemlibpki.tsl.TslValidator;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.AggregateTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.PersistTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.PersistTslUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.SignTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@Slf4j
@DisplayName("PKI TSL approval tests.")
@Order(1)
class TslApprovalTests extends ApprovalTestsBase {

  public static final X509Certificate VALID_ISSUER_CERT_TSL_CA8 =
      CertReader.readX509(TestSuiteConstants.VALID_ISSUER_CERT_TSL_CA8_PATH);

  private TslOperation formatTsl(final DocToBytesOption docToBytesOption) {

    return tslContainer -> {
      final byte[] tslBytes = tslContainer.getAsTslBytes();

      final Document tslDoc = TslConverter.bytesToDoc(tslBytes);

      final byte[] tslByteFormatted = TslConverter.docToBytes(tslDoc, docToBytesOption);

      final P12Container p12Container =
          P12Reader.getContentFromP12(defaultTslSigner, tslSignerKeystorePassw);

      final Document tslDocFormatted = TslConverter.bytesToDoc(tslByteFormatted);

      TslSigner.builder().tslToSign(tslDocFormatted).tslSignerP12(p12Container).build().sign();
      return new TslContainer(tslDocFormatted);
    };
  }

  /** gematikId: UE_PKI_TC_0102_001 */
  @Test
  @Afo(afoId = "GS-A_4649", description = "TUC_PKI_020: XML-Dokument validieren")
  @DisplayName("Test update of TSL with different XML format (pretty print)")
  void verifyUpdateTrustStoreInTestObject(final TestInfo testInfo) {

    testCaseMessage(testInfo);

    initialStateWithAlternativeTemplate();

    updateTrustStore(
        "case 1 - AlternativeCaPrettyPrint.",
        newTslGenerator("prettyPrintedTslPart", formatTsl(DocToBytesOption.PRETTY_PRINT))
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    updateTrustStore(
        "case 2 - AlternativeCaNoLineBreaks.",
        newTslGenerator("noLineBreaksInTslPart", formatTsl(DocToBytesOption.NO_LINE_BREAKS))
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));
  }

  /** gematikId: UE_PKI_TC_0104_004 */
  @Test
  @Afo(
      afoId = "TIP1-A_5120",
      description = "Clients des TSL-Dienstes: HTTP-Komprimierung unterstützen")
  @DisplayName("Test compression of TSL download")
  void verifyTslDownloadCompression(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getCurrentNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds() + 5L,
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
  void verifyIrregularDifferencesBetweenCurrentAndNewTsls(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final TslDownload initialTslDownload = initialTslDownloadByTestObject();

    log.info("case 0: same tsl");

    initialTslDownload.waitUntilTslDownloadCompletedOptional(
        tslSequenceNr.getExpectedNrInTestObject());

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);

    final BiConsumer<Integer, String> verifyForSeqNr =
        (offeredSeqNr, tslName) -> {
          log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredSeqNr);
          final TslDownload tslDownload =
              newTslGenerator(tslName)
                  .getTslDownloadWithTemplateAndSigner(
                      offeredSeqNr,
                      CreateTslTemplate.alternativeTsl(),
                      defaultTslSigner,
                      SIGNER_KEY_USAGE_CHECK_ENABLED,
                      SIGNER_VALIDITY_CHECK_ENABLED);

          tslSequenceNr.setLastOfferedNr(offeredSeqNr);
          tslDownload.waitUntilTslDownloadCompletedOptional(
              tslSequenceNr.getExpectedNrInTestObject());

          useCaseWithCert(
              getPathOfAlternativeCertificate(),
              USECASE_INVALID,
              OCSP_RESP_WITH_PROVIDED_CERT,
              OCSP_REQUEST_DO_NOT_EXPECT);
        };

    log.info("case 1: new seqNr is smaller");
    verifyForSeqNr.accept(tslSequenceNr.getCurrentNrInTestObject() - 1, "case1SmallerSeqNr");

    log.info("case 2: different tsl ids, but same seqNr");
    verifyForSeqNr.accept(
        tslSequenceNr.getCurrentNrInTestObject(), "case2DifferentTslIdsSameSeqNr");

    log.info("case 3: same tsl ids, but new seqNr is higher");
    log.info(
        "initial tsl seqNr: {}, id: {}",
        initialTslDownload.getTsl().getId(),
        initialTslDownload.getTsl().getSchemeInformation().getTSLSequenceNumber());

    final TslOperation rewriteTslIdToInitial =
        tslContainer -> {
          final TrustStatusListType tsl = tslContainer.getAsTsl();

          final String newId = initialTslDownload.getTsl().getId();
          tsl.setId(newId);

          return newTslGenerator().signTslOperation(defaultTslSigner).apply(tsl);
        };

    updateTrustStore(
        "Offer a TSL with the same tsl id, but new (incremented) seqNr.",
        newTslGenerator("sameTslId", rewriteTslIdToInitial)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_IGNORE,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));
  }

  /** gematikId: UE_PKI_TC_0102_004 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 6")
  @DisplayName("Test bad CA certificate is not extractable from TSL")
  void verifyForBadCertificateOfTSPService(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    updateTrustStore(
        "Offer a TSL with alternative CAs whose ASN1 structure is invalid.",
        newTslGenerator("altCaWithBrokenAsn1")
            .getStandardTslDownload(CreateTslTemplate.defectAlternativeCaBrokenTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_006 */
  @Test
  @Afo(afoId = "GS-A_4749", description = "TUC_PKI_007: Prüfung Zertifikatstyp - Schritt 8")
  @DisplayName("Test CA certificate with missing service information extension in TSL")
  void verifyForWrongServiceInfoExtCertificateOfTSPService(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    updateTrustStore(
        "Offer a TSL with alternative CAs whose ServiceInformationExtension elements are"
            + " wrong.",
        newTslGenerator("altCaWithBadServiceInformationExtensions")
            .getStandardTslDownload(CreateTslTemplate.defectAlternativeCaWrongSrvInfoExtTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_IGNORE));

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_007 */
  @Test
  @Afo(afoId = "A_17700", description = "TSL-Auswertung ServiceTypeIdentifier \"unspecified\"")
  @DisplayName("Test CA certificate with ServiceTypeIdentifier \"unspecified\" in TSL")
  void verifyForUnspecifiedServiceTypeIdentifierOfTSPService(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    updateTrustStore(
        "Import TSL with ServiceTypeIdentifier \"unspecified\".",
        newTslGenerator("altCaUnspecifiedServiceTypeIdentifier")
            .getStandardTslDownload(CreateTslTemplate.alternativeCaUnspecifiedStiTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID));
  }

  /** gematikId: UE_PKI_TS_0302_037 */
  @Test
  @Afo(afoId = "GS-A_4652", description = "TUC_PKI_018: Zertifikatsprüfung in der TI - Schritt 5a")
  @DisplayName("Test CA certificate in TSL is revoked and EE certificate is issued later.")
  void verifyRevokedCaCertificateInTslLater(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    waitForOcspCacheToExpire();

    updateTrustStore(
        "Offer a TSL with alternative CAs with ServiceStatus REVOKED.",
        newTslGenerator("altCaRevoked")
            .getStandardTslDownload(CreateTslTemplate.alternativeCaRevokedTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_038 */
  @Test
  @Afo(afoId = "GS-A_4652", description = "TUC_PKI_018: Zertifikatsprüfung in der TI - Schritt 5")
  @DisplayName("Test CA certificate in TSL is revoked and EE certificate is issued earlier.")
  void verifyRevokedCaCertificateInTslInPast(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    waitForOcspCacheToExpire();

    final TslOperation rewriteStatusStartingTimeToNowPlusOneDay =
        tslContainer -> {
          final ZonedDateTime newStatusStartingTime = GemLibPkiUtils.now().plusDays(1);

          final TrustStatusListType tsl = tslContainer.getAsTsl();

          TslModifier.modifyStatusStartingTime(
              tsl,
              PkitsConstants.GEMATIK_TEST_TSP,
              null,
              TslConstants.SVCSTATUS_REVOKED,
              newStatusStartingTime);

          return newTslGenerator().signTslOperation(defaultTslSigner).apply(tsl);
        };

    updateTrustStore(
        "Offer a TSL with alternative CAs, ServiceStatus REVOKED, StatusStartingTime one day in the"
            + " future.",
        newTslGenerator("altCaRevokedInFuture", rewriteStatusStartingTimeToNowPlusOneDay)
            .getStandardTslDownload(CreateTslTemplate.alternativeCaRevokedLaterTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));
  }

  /** gematikId: UE_PKI_TC_0105_009 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 4")
  @Afo(afoId = "GS-A_4651", description = "TUC_PKI_012: XML-Signatur-Prüfung")
  @DisplayName("Test TSL signature invalid - \"to be signed block\" with integrity violation")
  void verifyTslSignatureInvalid(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final TslOperation rewriteMailToInvalidateSignature =
        tslContainer -> {
          final byte[] tslBytes = tslContainer.getAsTslBytes();
          assertThat(TslValidator.checkSignature(tslBytes, VALID_ISSUER_CERT_TSL_CA8)).isTrue();

          // break integrity of TSL and verify signature again
          final String mailToStrOld = getFirstSchemeOperatorMailAddressOfTsl(tslBytes);
          final String mailToStrNew = "mailto:signatureInvalid@gematik.de";
          final String tslStr = new String(tslBytes, StandardCharsets.UTF_8);
          final byte[] brokenTslBytes =
              tslStr.replace(mailToStrOld, mailToStrNew).getBytes(StandardCharsets.UTF_8);

          log.info("Verify test tsl has wrong signature.");
          assertThat(TslValidator.checkSignature(brokenTslBytes, VALID_ISSUER_CERT_TSL_CA8))
              .isFalse();

          return new TslContainer(brokenTslBytes);
        };

    updateTrustStore(
        "Offer a TSL with alternative CAs. The signature of the TSL is invalid.",
        newTslGenerator("brokenSignatureByChangedEmail", rewriteMailToInvalidateSignature)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_IGNORE,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_IGNORE));

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
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

  private Callable<Boolean> achievedTslHistoryCount(
      final int expectedPrimaryEndpointRepetitions, final int expectedBackupEndpointRepetitions) {
    return () -> {
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

      final boolean b1 = (primaryTslCount == expectedPrimaryEndpointRepetitions);
      final boolean b2 = (backupTslCount == expectedBackupEndpointRepetitions);

      log.info("primaryTslCount: {}, backupTslCount  {}", primaryTslCount, backupTslCount);

      return b1 && b2;
    };
  }

  private static final int MAX_ENDPOINT_REPETITIONS = 4;

  private void updateTrustStoreAndWaitWithCount(
      final TslDownload tslDownload,
      final TslProviderEndpointsConfig tslProviderEndpointsConfig,
      final int expectedPrimaryEndpointRepetitions,
      final int expectedBackupEndpointRepetitions) {

    waitForOcspCacheToExpire();

    waitForSync(tslSequenceNr.getCurrentNrInTestObject());

    TslProviderManager.clearTslHistory(tslProvUri);

    tslDownload.configureOcspResponderTslSignerStatusGood();

    log.info("configure TslProvider to return {}", tslProviderEndpointsConfig);
    TestEnvironment.configureTslProvider(
        tslProvUri,
        tslDownload.getTslBytes(),
        TSL_DOWNLOAD_POINT_PRIMARY,
        tslProviderEndpointsConfig);

    final Callable<Boolean> callable =
        achievedTslHistoryCount(
            expectedPrimaryEndpointRepetitions, expectedBackupEndpointRepetitions);

    PkitsTestSuiteUtils.waitForEventMillis(
        "TslDownloadHistoryHasEntry for seqNr " + tslSequenceNr.getExpectedNrInTestObject(),
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds(),
        100,
        callable);
  }

  /** gematikId: UE_PKI_TC_0104_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3 und 4")
  @DisplayName("Test TSL download not possible")
  void verifyRetryFailingTslDownload(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredSeqNr);

    final TslDownload tslDownload =
        newTslGenerator("alternative").getStandardTslDownload(CreateTslTemplate.alternativeTsl());

    updateTrustStoreAndWaitWithCount(
        tslDownload,
        TslProviderEndpointsConfig.PRIMARY_404_BACKUP_404,
        MAX_ENDPOINT_REPETITIONS,
        MAX_ENDPOINT_REPETITIONS);

    assertNoOcspRequest(tslDownload);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0104_002 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3 und 4")
  @DisplayName("Test TSL download on primary endpoint not possible")
  void verifyUseBackupTslDownload(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredSeqNr);

    final TslDownload tslDownload =
        newTslGenerator("alternativeTsl")
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl());

    updateTrustStoreAndWaitWithCount(
        tslDownload,
        TslProviderEndpointsConfig.PRIMARY_404_BACKUP_200,
        MAX_ENDPOINT_REPETITIONS,
        1);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(offeredSeqNr);

    tslDownload.waitUntilOcspRequestForSigner(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0104_003 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3")
  @DisplayName("TSL with invalid OID of download addresses.")
  void verifyForTslWithInvalidOidDownloadAddresses(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    /** TSLTypeID 336 */
    final TslOperation modifyPrimaryDownloadOid =
        tslContainer -> {
          final TrustStatusListType tsl = tslContainer.getAsTsl();
          final MultiLangStringType textualInformation =
              (MultiLangStringType)
                  tsl.getSchemeInformation().getPointersToOtherTSL().getOtherTSLPointer().stream()
                      .filter(
                          TslUtils.tslDownloadUrlMatchesOid(
                              TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY))
                      .findFirst()
                      .orElseThrow()
                      .getAdditionalInformation()
                      .getTextualInformationOrOtherInformation()
                      .get(0);

          final String dummyOid = "1.2.276.0.76.4.10";
          textualInformation.setValue(dummyOid);
          return new TslContainer(tsl);
        };

    final String tslName = "modifiedPrimaryDownloadOid";
    final AggregateTslOperation aggregate =
        AggregateTslOperation.builder()
            .chained(
                newTslGenerator(tslName).getStandardTslOperation(tslSequenceNr.getNextTslSeqNr()))
            .chained(modifyPrimaryDownloadOid)
            .chained(newTslGenerator().signTslOperation(defaultTslSigner))
            .chained(new PersistTslOperation(currentTestInfo, tslName))
            .build();

    final TslContainer tslContainer = aggregate.apply(CreateTslTemplate.defaultTsl());

    final TslDownload tslDownload =
        newTslGenerator("defectPrimaryDownloadOid")
            .getTslDownload(tslContainer.getAsTslBytes(), defaultTslSigner);

    updateTrustStore(
        "Offer a TSL with default CAs and defect OID in primary download point.",
        tslDownload,
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), USECASE_VALID));

    log.info(
        "Offer the default TSL. The test object is expected to download from the backup download"
            + " point because the primary download address in the previous TSL does not exist"
            + " (wrong OID). <default>");
    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredSeqNr);

    updateTrustStoreAndWaitWithCount(
        newTslGenerator("default").getStandardTslDownload(CreateTslTemplate.defaultTsl()),
        TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200,
        0,
        1);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(offeredSeqNr);

    tslDownload.waitUntilOcspRequestForSigner(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0103_002 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(
      afoId = "TODO - GS-A_4648",
      description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 7")
  @DisplayName("NOT IMPLEMENTED YET - TSL in the system is out of time.")
  @Disabled("NOT IMPLEMENTED YET")
  void verifyForTslInSystemIsOutOfTime(final TestInfo testInfo) {
    failNotImplemented();
  }

  /** gematikId: UE_PKI_TC_0105_006 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4649", description = "TUC_PKI_020: XML-Dokument validieren - Schritt 2")
  @DisplayName("TSL with not well-formed XML structure.")
  void verifyForTslNotWellFormedXmlStructure(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final TslOperation breakXmlStructure =
        tslContainer -> {
          final byte[] tslBytes = tslContainer.getAsTslBytes();
          final byte[] brokenTslBytes = Arrays.copyOfRange(tslBytes, 0, tslBytes.length - 1);
          return new TslContainer(brokenTslBytes);
        };

    final TslGenerator tslGenerator =
        newTslGenerator("notWellFormedXmlStructure", breakXmlStructure);

    final TslContainer tslToGenerateFilename =
        tslGenerator
            .getStandardTslOperation(tslGenerator.getTslSeqNr())
            .apply(CreateTslTemplate.alternativeTsl());

    final Path tslOutputFile =
        PersistTslUtils.generateTslFilename(
            currentTestInfo, "notWellFormedXmlStructure", tslToGenerateFilename.getAsTsl());

    final TslDownload tslDownload =
        tslGenerator.getTslDownloadWithTemplateAndSigner(
            tslOutputFile,
            tslGenerator.getTslSeqNr(),
            CreateTslTemplate.alternativeTsl(),
            defaultTslSigner,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    updateTrustStore(
        "Offer a TSL with alternative CAs and invalid XML structure.",
        tslDownload,
        OCSP_REQUEST_DO_NOT_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_007 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4649", description = "TUC_PKI_020: XML-Dokument validieren - Schritt 3")
  @DisplayName("TSL with invalid XML schema or schema non-compliant element.")
  void verifyForTslInvalidXmlSchemaOrNonCompliantElement(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    for (final int dataVariant : List.of(1, 2)) {
      final TslOperation modifyTsl;
      final String phaseName;
      if (dataVariant == 1) {
        /* TSLTypeID 339 */
        // TSL_invalid_xmlNamespace_altCA.xml

        phaseName = "dataVariant1InvalidXmlSchema";
        modifyTsl =
            tslContainer -> {
              final byte[] tslBytes = tslContainer.getAsTslBytes();
              final String tslBytesStr = new String(tslBytes, StandardCharsets.UTF_8);

              final String oldNamespace = "http://uri.etsi.org/02231/v2#";
              final String newNamespace = "http://invalidnamespace.gematik.net/02231/v2#";

              assertThat(tslBytesStr).contains(oldNamespace);
              assertThat(tslBytesStr).doesNotContain(newNamespace);

              final String newTslBytesStr = tslBytesStr.replace(oldNamespace, newNamespace);

              assertThat(newTslBytesStr).doesNotContain(oldNamespace);
              assertThat(newTslBytesStr).contains(newNamespace);

              return new TslContainer(newTslBytesStr.getBytes(StandardCharsets.UTF_8));
            };

      } else {
        /* TSLTypeID 366 */
        // TSL_invalid_xmlNonEtsiTag_altCA
        phaseName = "dataVariant2UnknownXmlElement";
        modifyTsl =
            tslContainer -> {
              final Document tslDoc = tslContainer.getAsTslDoc();

              final Element unknownElement = tslDoc.createElement("ThisDoesNotBelongToETSI");
              unknownElement.setTextContent("IF THIS IS ACCEPTED, THE TESTRUN FAILED");
              final NodeList nodeList = tslDoc.getElementsByTagName("TrustServiceProviderList");
              final Node node = nodeList.item(0);
              node.getParentNode().insertBefore(unknownElement, node.getNextSibling());

              return new TslContainer(tslDoc);
            };
      }

      final TslOperation aggregateTslOperation =
          new AggregateTslOperation(
              modifyTsl,
              new SignTslOperation(
                  defaultTslSigner,
                  tslSignerKeystorePassw,
                  SIGNER_KEY_USAGE_CHECK_ENABLED,
                  SIGNER_VALIDITY_CHECK_ENABLED));

      final TslGenerator tslGenerator = newTslGenerator(phaseName, aggregateTslOperation);

      final TslContainer tslToGenerateFilename =
          tslGenerator
              .getStandardTslOperation(tslGenerator.getTslSeqNr())
              .apply(CreateTslTemplate.alternativeTsl());

      final Path tslOutputFile =
          PersistTslUtils.generateTslFilename(
              currentTestInfo, phaseName, tslToGenerateFilename.getAsTsl());

      final TslDownload tslDownload =
          tslGenerator.getTslDownloadWithTemplateAndSigner(
              tslOutputFile,
              tslGenerator.getTslSeqNr(),
              CreateTslTemplate.alternativeTsl(),
              defaultTslSigner,
              SIGNER_KEY_USAGE_CHECK_ENABLED,
              SIGNER_VALIDITY_CHECK_ENABLED);

      updateTrustStore(
          "Offer a TSL with alternative CAs and invalid XML structure.",
          tslDownload,
          OCSP_REQUEST_DO_NOT_EXPECT,
          withUseCase(
              getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));
    }

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }
}
