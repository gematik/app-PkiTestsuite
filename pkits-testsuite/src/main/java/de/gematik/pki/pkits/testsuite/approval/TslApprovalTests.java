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

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TSL_SIGNER;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.ALTERNATIVE_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.DEFAULT_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.common.tsl.TslDownload.tslDownloadHistoryHasSpecificEntry;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
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
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload.ClearConfigAfterWaiting;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.PersistTslUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslDownloadGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.AggregateTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.SignTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.tsl.provider.api.TslDownloadEndpointType;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderEndpointsConfig;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@Slf4j
@DisplayName("PKI TSL approval tests.")
@Order(1)
class TslApprovalTests extends ApprovalTestsBase {

  private TslOperation formatTsl(final DocToBytesOption docToBytesOption) {

    return tslContainer -> {
      final byte[] tslUnsignedBytes = tslContainer.getAsTslUnsignedBytes();

      final Document tslUnsignedDoc = TslConverter.bytesToDoc(tslUnsignedBytes);

      final byte[] tslUnsignedByteFormatted =
          TslConverter.docToBytes(tslUnsignedDoc, docToBytesOption);

      final Document tslUnsignedDocFormatted = TslConverter.bytesToDoc(tslUnsignedByteFormatted);

      TslSigner.builder()
          .tslToSign(tslUnsignedDocFormatted)
          .tslSignerP12(DEFAULT_TSL_SIGNER)
          .build()
          .sign();
      return new TslContainer(tslUnsignedDocFormatted);
    };
  }

  /** gematikId: UE_PKI_TC_0102_001 */
  @Test
  @Afo(afoId = "A_17688", description = "Nutzung des ECC-RSA-Vertrauensraumes (ECC-Migration)")
  @Afo(afoId = "GS-A_4649", description = "TUC_PKI_020: XML-Dokument validieren")
  @DisplayName("Test update of TSL with different XML format (pretty print)")
  void verifyUpdateTrustStoreInTestObject() {

    initialStateWithAlternativeTemplate();

    updateTrustStore(
        "case 1 - AlternativeCaPrettyPrint.",
        newTslDownloadGenerator("prettyPrintedTslPart", formatTsl(DocToBytesOption.PRETTY_PRINT))
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_VALID, OCSP_REQUEST_EXPECT));

    updateTrustStore(
        "case 2 - AlternativeCaNoLineBreaks.",
        newTslDownloadGenerator("noLineBreaksInTslPart", formatTsl(DocToBytesOption.NO_LINE_BREAKS))
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_VALID, OCSP_REQUEST_EXPECT));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0104_004 */
  @Test
  @Afo(
      afoId = "TIP1-A_5120",
      description = "Clients des TSL-Dienstes: HTTP-Komprimierung unterstützen")
  @DisplayName("Test compression of TSL download")
  void verifyTslDownloadCompression() {

    initialState();

    TestEnvironment.configureTslProvider(
        tslProviderUri, "dummy".getBytes(), TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200);

    final int tslSequenceNrToQuery = TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for tslSeqNr " + tslSequenceNrToQuery,
        getTslDownloadIntervalWithExtraTimeSeconds(),
        tslDownloadHistoryHasSpecificEntry(
            tslProviderUri, tslSequenceNrToQuery, TslDownloadEndpointType.XML_ENDPOINTS));

    final List<TslRequestHistoryEntryDto> historyEntryDtos =
        TslProviderManager.getTslRequestHistoryPart(
            tslProviderUri, tslSequenceNrToQuery, TslDownloadEndpointType.XML_ENDPOINTS);

    assertThat(historyEntryDtos).as("No TSL download requests received").isNotEmpty();

    final TslRequestHistoryEntryDto historyEntryDto =
        historyEntryDtos.get(historyEntryDtos.size() - 1);

    assertThat(historyEntryDto.isGzipCompressed())
        .as("TSL download requests has to contain accept-encoding: gzip")
        .isTrue();

    assertThat(historyEntryDto.getProtocol())
        .as("TSL download requests has to be with http version 1.1")
        .isEqualTo("HTTP/1.1");

    TestEnvironment.clearTslProviderConfig(tslProviderUri);
    TslProviderManager.clearTslHistory(tslProviderUri);
  }

  /** gematikId: UE_PKI_TC_0103_004 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 6")
  @DisplayName("Test TSL service does not provide updated TSL")
  void verifyIrregularDifferencesBetweenCurrentAndNewTsls() {

    initialState();

    final TslDownload initialTslDownload = initialTslDownloadByTestObject();

    log.info("case 0: same tsl (TSL update is not expected)");

    initialTslDownload.configureOcspResponderForTslSigner();
    initialTslDownload.waitForTslDownload(
        tslSequenceNr.getExpectedNrInTestObject(),
        TslDownloadEndpointType.ANY_ENDPOINT,
        ClearConfigAfterWaiting.CLEAR_CONFIG);
    initialTslDownload.waitUntilOcspRequestForSignerOptional();

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);

    final BiConsumer<Integer, String> verifyForTslSeqNr =
        (offeredTslSeqNr, tslName) -> {
          log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);
          final TslDownload tslDownload =
              newTslDownloadGenerator(tslName)
                  .getTslDownloadWithTemplateAndSigner(
                      offeredTslSeqNr,
                      CreateTslTemplate.alternativeTsl(),
                      DEFAULT_TSL_SIGNER,
                      DEFAULT_TRUST_ANCHOR,
                      SIGNER_KEY_USAGE_CHECK_ENABLED,
                      SIGNER_VALIDITY_CHECK_ENABLED);

          tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
          tslDownload.waitUntilTslDownloadCompletedOptional(
              tslSequenceNr.getExpectedNrInTestObject());

          useCaseWithCert(
              ALTERNATIVE_CLIENT_CERTS_CONFIG,
              USECASE_INVALID,
              OCSP_RESP_WITH_PROVIDED_CERT,
              OCSP_REQUEST_DO_NOT_EXPECT);
        };

    log.info("case 1: new tslSeqNr is smaller");
    verifyForTslSeqNr.accept(tslSequenceNr.getCurrentNrInTestObject() - 1, "case1SmallerTslSeqNr");

    log.info("case 2: different tslId, but same tslSeqNr");
    verifyForTslSeqNr.accept(
        tslSequenceNr.getCurrentNrInTestObject(), "case2DifferentTslIdsSameTslSeqNr");

    log.info("case 3: same tslId, but new tslSeqNr is higher");
    log.info(
        "initial tslSeqNr: {}, id: {}",
        initialTslDownload.getTslUnsigned().getId(),
        initialTslDownload.getTslUnsigned().getSchemeInformation().getTSLSequenceNumber());

    final TslOperation rewriteTslIdToInitial =
        tslContainer -> {
          final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();

          final String newId = initialTslDownload.getTslUnsigned().getId();
          tslUnsigned.setId(newId);

          return newTslDownloadGenerator().signTslOperation(DEFAULT_TSL_SIGNER).apply(tslUnsigned);
        };

    updateTrustStore(
        "Offer a TSL with the same tslId, but new (incremented) tslSeqNr.",
        newTslDownloadGenerator("sameTslId", rewriteTslIdToInitial)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_IGNORE,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));
  }

  /** gematikId: UE_PKI_TC_0102_004 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 6")
  @DisplayName("Test bad CA certificate is not extractable from TSL")
  void verifyForBadCertificateOfTSPService() {

    initialState();

    updateTrustStore(
        "Offer a TSL with alternative CAs whose ASN1 structure is invalid.",
        newTslDownloadGenerator("altCaWithBrokenAsn1")
            .getStandardTslDownload(CreateTslTemplate.defectAlternativeCaBrokenTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID));

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0102_006 */
  @Test
  @Afo(afoId = "GS-A_4749", description = "TUC_PKI_007: Prüfung Zertifikatstyp - Schritt 8")
  @DisplayName("Test CA certificate with missing service information extension in TSL")
  void verifyForWrongServiceInfoExtCertificateOfTSPService() {

    initialState();

    updateTrustStore(
        "Offer a TSL with alternative CAs whose ServiceInformationExtension elements are"
            + " wrong.",
        newTslDownloadGenerator("altCaWithBadServiceInformationExtensions")
            .getStandardTslDownload(CreateTslTemplate.defectAlternativeCaWrongSrvInfoExtTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_IGNORE));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0102_007 */
  @Test
  @Afo(afoId = "A_17700", description = "TSL-Auswertung ServiceTypeIdentifier \"unspecified\"")
  @DisplayName("Test CA certificate with ServiceTypeIdentifier \"unspecified\" in TSL")
  void verifyForUnspecifiedServiceTypeIdentifierOfTSPService() {
    // NOTE: test case outdated

    initialState();

    updateTrustStore(
        "Import TSL with ServiceTypeIdentifier \"unspecified\".",
        newTslDownloadGenerator("altCaUnspecifiedServiceTypeIdentifier")
            .getStandardTslDownload(CreateTslTemplate.alternativeCaUnspecifiedStiTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_VALID));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TS_0302_037 */
  @Test
  @Afo(afoId = "GS-A_4652", description = "TUC_PKI_018: Zertifikatsprüfung in der TI - Schritt 5a")
  @DisplayName("Test CA certificate in TSL is revoked and EE certificate is issued later.")
  void verifyRevokedCaCertificateInTslLater() {

    initialState();

    waitForOcspCacheToExpire();

    updateTrustStore(
        "Offer a TSL with alternative CAs with ServiceStatus REVOKED.",
        newTslDownloadGenerator("altCaRevoked")
            .getStandardTslDownload(CreateTslTemplate.alternativeCaRevokedTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TS_0302_038 */
  @Test
  @Afo(afoId = "GS-A_4652", description = "TUC_PKI_018: Zertifikatsprüfung in der TI - Schritt 5")
  @DisplayName("Test CA certificate in TSL is revoked and EE certificate is issued earlier.")
  void verifyRevokedCaCertificateInTslInPast() {

    initialState();

    waitForOcspCacheToExpire();

    final TslOperation rewriteStatusStartingTimeToNowPlusOneDay =
        tslContainer -> {
          final ZonedDateTime newStatusStartingTime = GemLibPkiUtils.now().plusDays(1);

          final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();

          TslModifier.modifyStatusStartingTime(
              tslUnsigned,
              PkitsConstants.GEMATIK_TEST_TSP,
              null,
              TslConstants.SVCSTATUS_REVOKED,
              newStatusStartingTime);

          return newTslDownloadGenerator().signTslOperation(DEFAULT_TSL_SIGNER).apply(tslUnsigned);
        };

    updateTrustStore(
        "Offer a TSL with alternative CAs, ServiceStatus REVOKED, StatusStartingTime one day in the"
            + " future.",
        newTslDownloadGenerator("altCaRevokedInFuture", rewriteStatusStartingTimeToNowPlusOneDay)
            .getStandardTslDownload(CreateTslTemplate.alternativeCaRevokedLaterTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_VALID, OCSP_REQUEST_EXPECT));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_009 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 4")
  @Afo(afoId = "GS-A_4651", description = "TUC_PKI_012: XML-Signatur-Prüfung")
  @DisplayName("Test TSL signature invalid - \"to be signed block\" with integrity violation")
  void verifyTslSignatureInvalid() {

    initialState();

    final TslOperation rewriteMailToInvalidateSignature =
        tslContainer -> {
          final byte[] tslUnsignedBytes = tslContainer.getAsTslUnsignedBytes();
          assertThat(TslValidator.checkSignature(tslUnsignedBytes, DEFAULT_TRUST_ANCHOR)).isTrue();

          // break integrity of TSL and verify signature again
          final String mailToStrOld = getFirstSchemeOperatorMailAddressOfTsl(tslUnsignedBytes);
          final String mailToStrNew = "mailto:signatureInvalid@gematik.de";
          final String tslUnsignedStr = new String(tslUnsignedBytes, StandardCharsets.UTF_8);
          final byte[] brokenTslUnsignedBytes =
              tslUnsignedStr.replace(mailToStrOld, mailToStrNew).getBytes(StandardCharsets.UTF_8);

          log.info("Verify test tsl has wrong signature.");
          assertThat(TslValidator.checkSignature(brokenTslUnsignedBytes, DEFAULT_TRUST_ANCHOR))
              .isFalse();

          return new TslContainer(brokenTslUnsignedBytes);
        };

    updateTrustStore(
        "Offer a TSL with alternative CAs. The signature of the TSL is invalid.",
        newTslDownloadGenerator("brokenSignatureByChangedEmail", rewriteMailToInvalidateSignature)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_IGNORE,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_IGNORE));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  private String getFirstSchemeOperatorMailAddressOfTsl(final byte[] tslBytes) {
    final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(tslBytes);
    return tslUnsigned
        .getSchemeInformation()
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
              tslProviderUri,
              tslSequenceNr.getExpectedNrInTestObject(),
              TslDownloadEndpointType.XML_ENDPOINTS);

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

    tslDownload.configureOcspResponderForTslSigner();

    log.info("configure TslProvider to return {}", tslProviderEndpointsConfig);
    TestEnvironment.configureTslProvider(
        tslProviderUri, tslDownload.getTslBytes(), tslProviderEndpointsConfig);

    OcspResponderManager.clearOcspHistory(ocspResponderUri);
    TslProviderManager.clearTslHistory(tslProviderUri);

    final Callable<Boolean> achievedTslHistoryCountFunc =
        achievedTslHistoryCount(
            expectedPrimaryEndpointRepetitions, expectedBackupEndpointRepetitions);

    PkitsTestSuiteUtils.waitForEventMillis(
        "TslDownloadHistoryHasEntry for tslSeqNr " + tslSequenceNr.getExpectedNrInTestObject(),
        getTslDownloadIntervalWithExtraTimeSeconds(),
        100,
        achievedTslHistoryCountFunc);
  }

  private void initialStateWithoutCleanUp() {

    log.info("START initialStateWithoutCleanUp\n  {}", PkitsTestSuiteUtils.getCallerTrace());

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);

    final TslDownload tslDownload =
        newTslDownloadGenerator("initialStateWithoutCleanUp")
            .getTslDownloadWithTemplateAndSigner(
                offeredTslSeqNr,
                CreateTslTemplate.defaultTsl(),
                DEFAULT_TSL_SIGNER,
                DEFAULT_TRUST_ANCHOR,
                SIGNER_KEY_USAGE_CHECK_ENABLED,
                SIGNER_VALIDITY_CHECK_ENABLED);

    tslDownload.configureOcspResponderForTslSigner();
    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(
        tslSequenceNr.getExpectedNrInTestObject(),
        TslDownloadEndpointType.XML_ENDPOINTS,
        ClearConfigAfterWaiting.DO_NOT_CLEAR_CONFIG);

    tslDownload.waitUntilOcspRequestForTslSigner(
        tslSequenceNr.getExpectedNrInTestObject(), ClearConfigAfterWaiting.DO_NOT_CLEAR_CONFIG);
    tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);

    log.info("END initialStateWithoutCleanUp\n  {}\n\n", PkitsTestSuiteUtils.getCallerTrace());
  }

  /** gematikId: UE_PKI_TC_0104_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3 und 4")
  @DisplayName("Test TSL download not possible")
  void verifyRetryFailingTslDownload() {

    initialState();

    // NOTE we need this step as the test object continues downloading TSLs and should not receive
    // errors during re-configuration of the TSL provider
    initialStateWithoutCleanUp();

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);

    final TslDownload tslDownload =
        newTslDownloadGenerator(TslDownloadGenerator.TSL_NAME_ALTERNATIVE)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl());

    updateTrustStoreAndWaitWithCount(
        tslDownload,
        TslProviderEndpointsConfig.PRIMARY_404_BACKUP_404,
        MAX_ENDPOINT_REPETITIONS,
        MAX_ENDPOINT_REPETITIONS);

    assertNoOcspRequest(tslDownload);

    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForTslSigner(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0104_002 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 3 und 4")
  @DisplayName("Test TSL download on primary endpoint not possible")
  void verifyUseBackupTslDownload() {

    initialState();

    // NOTE we need this step as the test object continues downloading TSLs and should not receive
    // errors during re-configuration of the TSL provider
    initialStateWithoutCleanUp();

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);

    final TslDownload tslDownload =
        newTslDownloadGenerator(TslDownloadGenerator.TSL_NAME_ALTERNATIVE)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl());

    updateTrustStoreAndWaitWithCount(
        tslDownload,
        TslProviderEndpointsConfig.PRIMARY_404_BACKUP_200,
        MAX_ENDPOINT_REPETITIONS,
        1);

    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);

    tslDownload.waitUntilOcspRequestForTslSigner(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);

    useCaseWithCert(
        ALTERNATIVE_CLIENT_CERTS_CONFIG,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0104_003 */
  @Test
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 1")
  @Afo(afoId = "GS-A_4647", description = "TUC_PKI_016: Download der TSL-Datei - Schritt 2 und 3")
  @Afo(afoId = "GS-A_4646", description = "TUC_PKI_017: Lokalisierung TSL Download-Adressen")
  @DisplayName("TSL with invalid OID of download addresses.")
  void verifyForTslWithInvalidOidDownloadAddresses() {

    initialState();

    /* TSLTypeID 336 */
    final TslOperation modifyPrimaryDownloadOid =
        tslContainer -> {
          final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();
          final MultiLangStringType textualInformation =
              (MultiLangStringType)
                  tslUnsigned
                      .getSchemeInformation()
                      .getPointersToOtherTSL()
                      .getOtherTSLPointer()
                      .stream()
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
          return new TslContainer(tslUnsigned);
        };

    final String tslName = "modifiedPrimaryDownloadOid";
    final AggregateTslOperation aggregate =
        AggregateTslOperation.builder()
            .chained(
                newTslDownloadGenerator(tslName)
                    .getStandardTslOperation(tslSequenceNr.getNextTslSeqNr()))
            .chained(modifyPrimaryDownloadOid)
            .chained(newTslDownloadGenerator().signTslOperation(DEFAULT_TSL_SIGNER))
            .build();

    final TslContainer tslContainer = aggregate.apply(CreateTslTemplate.defaultTsl());

    final byte[] tslBytes = tslContainer.getAsTslUnsignedBytes();
    final Path tslFilename =
        PersistTslUtils.generateTslFilename(
            currentTestInfo, tslName, TslConverter.bytesToTslUnsigned(tslBytes));
    PersistTslUtils.saveBytes(tslFilename, tslBytes);

    final TslDownload tslDownloadDefectOid =
        newTslDownloadGenerator()
            .getTslDownload(tslBytes, DEFAULT_TSL_SIGNER, DEFAULT_TRUST_ANCHOR);

    updateTrustStore(
        "Offer a TSL with default CAs and defect OID in primary download point.",
        tslDownloadDefectOid,
        OCSP_REQUEST_EXPECT,
        withUseCase(DEFAULT_CLIENT_CERTS_CONFIG, USECASE_VALID));

    log.info(
        "Offer the default TSL. The test object is expected to download from the backup download"
            + " point because the primary download address in the previous TSL does not exist"
            + " (wrong OID)");
    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);
    final TslDownload tslDownload =
        newTslDownloadGenerator(TslDownloadGenerator.TSL_NAME_DEFAULT)
            .getStandardTslDownload(CreateTslTemplate.defaultTsl());
    updateTrustStoreAndWaitWithCount(
        tslDownload, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200, 0, 1);

    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitUntilOcspRequestForTslSigner(tslSequenceNr.getExpectedNrInTestObject());
    tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_006 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4649", description = "TUC_PKI_020: XML-Dokument validieren - Schritt 2")
  @DisplayName("TSL with not well-formed XML structure.")
  void verifyForTslNotWellFormedXmlStructure() {

    initialState();

    final TslOperation breakXmlStructure =
        tslContainer -> {
          final byte[] tslUnsignedBytes = tslContainer.getAsTslUnsignedBytes();
          final byte[] brokenTslBytes =
              Arrays.copyOfRange(tslUnsignedBytes, 0, tslUnsignedBytes.length - 1);
          return new TslContainer(brokenTslBytes);
        };

    final TslDownloadGenerator tslDownloadGenerator =
        newTslDownloadGenerator("notWellFormedXmlStructure", breakXmlStructure);

    final TslContainer tslToGenerateFilename =
        tslDownloadGenerator
            .getStandardTslOperation(tslDownloadGenerator.getTslSeqNr())
            .apply(CreateTslTemplate.alternativeTsl());

    final Path tslUnsignedOutputFile =
        PersistTslUtils.generateTslFilename(
            currentTestInfo, "notWellFormedXmlStructure", tslToGenerateFilename.getAsTslUnsigned());

    final TslDownload tslDownload =
        tslDownloadGenerator.getTslDownloadWithTemplateAndSigner(
            tslUnsignedOutputFile,
            tslDownloadGenerator.getTslSeqNr(),
            CreateTslTemplate.alternativeTsl(),
            DEFAULT_TSL_SIGNER,
            DEFAULT_TRUST_ANCHOR,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    updateTrustStore(
        "Offer a TSL with alternative CAs and invalid XML structure.",
        tslDownload,
        OCSP_REQUEST_DO_NOT_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
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
  void verifyForTslInvalidXmlSchemaOrNonCompliantElement() {

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
              final byte[] tslUnsignedBytes = tslContainer.getAsTslUnsignedBytes();
              final String tslUnsignedBytesStr =
                  new String(tslUnsignedBytes, StandardCharsets.UTF_8);

              final String oldNamespace = "http://uri.etsi.org/02231/v2#";
              final String newNamespace = "http://invalidnamespace.gematik.net/02231/v2#";

              assertThat(tslUnsignedBytesStr).contains(oldNamespace);
              assertThat(tslUnsignedBytesStr).doesNotContain(newNamespace);

              final String newTslUnsignedBytesStr =
                  tslUnsignedBytesStr.replace(oldNamespace, newNamespace);

              assertThat(newTslUnsignedBytesStr).doesNotContain(oldNamespace);
              assertThat(newTslUnsignedBytesStr).contains(newNamespace);

              return new TslContainer(newTslUnsignedBytesStr.getBytes(StandardCharsets.UTF_8));
            };

      } else {
        /* TSLTypeID 366 */
        // TSL_invalid_xmlNonEtsiTag_altCA
        phaseName = "dataVariant2UnknownXmlElement";
        modifyTsl =
            tslContainer -> {
              final Document tslUnsignedDoc = tslContainer.getAsTslUnsignedDoc();

              final Element unknownElement =
                  tslUnsignedDoc.createElement("ThisDoesNotBelongToETSI");
              unknownElement.setTextContent("IF THIS IS ACCEPTED, THE TESTRUN FAILED");
              final NodeList nodeList =
                  tslUnsignedDoc.getElementsByTagName("TrustServiceProviderList");
              final Node node = nodeList.item(0);
              node.getParentNode().insertBefore(unknownElement, node.getNextSibling());

              return new TslContainer(tslUnsignedDoc);
            };
      }

      final TslOperation aggregateTslOperation =
          new AggregateTslOperation(
              modifyTsl,
              new SignTslOperation(
                  DEFAULT_TSL_SIGNER,
                  SIGNER_KEY_USAGE_CHECK_ENABLED,
                  SIGNER_VALIDITY_CHECK_ENABLED));

      final TslDownloadGenerator tslDownloadGenerator =
          newTslDownloadGenerator(phaseName, aggregateTslOperation);

      final TslContainer tslToGenerateFilename =
          tslDownloadGenerator
              .getStandardTslOperation(tslDownloadGenerator.getTslSeqNr())
              .apply(CreateTslTemplate.alternativeTsl());

      final Path tslOutputFile =
          PersistTslUtils.generateTslFilename(
              currentTestInfo, phaseName, tslToGenerateFilename.getAsTslUnsigned());

      final TslDownload tslDownload =
          tslDownloadGenerator.getTslDownloadWithTemplateAndSigner(
              tslOutputFile,
              tslDownloadGenerator.getTslSeqNr(),
              CreateTslTemplate.alternativeTsl(),
              DEFAULT_TSL_SIGNER,
              DEFAULT_TRUST_ANCHOR,
              SIGNER_KEY_USAGE_CHECK_ENABLED,
              SIGNER_VALIDITY_CHECK_ENABLED);

      updateTrustStore(
          "Offer a TSL with alternative CAs and invalid XML structure.",
          tslDownload,
          OCSP_REQUEST_DO_NOT_EXPECT,
          withUseCase(
              ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));
    }

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }
}
