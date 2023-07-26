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

import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTests.TslUpdateExpectation.TSL_UPDATE_EXPECTED;
import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTests.TslUpdateExpectation.TSL_UPDATE_NOT_EXPECTED;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_DISABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_DISABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;
import static java.lang.Integer.max;
import static java.lang.Math.round;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusType;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.OcspResponderConfigDtoBuilder;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.BreakSignerTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI TSL signer approval tests.")
@Order(1)
class TslSignerApprovalTests extends ApprovalTestsBase {

  protected enum TslUpdateExpectation {
    TSL_UPDATE_EXPECTED,
    TSL_UPDATE_NOT_EXPECTED
  }

  private void updateTrustStoreUsingOcspResponderConfig(
      final TrustStatusListType tsl,
      final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep,
      final TslUpdateExpectation tslUpdateExpected,
      final Path certPath,
      final UseCaseResult useCaseResult) {

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(defaultOcspSigner);

    dtoBuilderStep.accept(dtoBuilder);

    log.info(
        "START updateTrustStoreUsingOcspResponderConfig - {}",
        PkitsTestSuiteUtils.getCallerTrace());
    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);
    final TslDownload tslDownload =
        newTslGenerator("updateTrustStoreUsingOcspResponderConfig").getStandardTslDownload(tsl);

    tslDownload.configureOcspResponderForTslSigner(dtoBuilder);
    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForTslSigner(tslSequenceNr.getExpectedNrInTestObject());

    if (tslUpdateExpected == TSL_UPDATE_EXPECTED) {
      tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);
    }
    final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour;

    if (useCaseResult == USECASE_VALID) {
      ocspRequestExpectationBehaviour = OCSP_REQUEST_EXPECT;
    } else {
      ocspRequestExpectationBehaviour = OCSP_REQUEST_DO_NOT_EXPECT;
    }

    useCaseWithCert(
        certPath, useCaseResult, OCSP_RESP_WITH_PROVIDED_CERT, ocspRequestExpectationBehaviour);
    log.info(
        "END updateTrustStoreUsingOcspResponderConfig - {}", PkitsTestSuiteUtils.getCallerTrace());
  }

  /** gematikId: UE_PKI_TC_0105_018 */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a")
  @DisplayName("Test missing OCSP signer in TSL for TSL signer certificate")
  @ValueSource(
      strings = {
        TestSuiteConstants.OCSP_SIGNER_NOT_IN_TSL_FILENAME,
        TestSuiteConstants.OCSP_SIGNER_DIFFERENT_KEY
      })
  void verifyMissingOcspSignerInTslForTslSignerCert(final String ocspSignerFilename) {

    initialState();

    final P12Container ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(ocspSignerFilename),
            ocspSettings.getSignerPassword());

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.signer(ocspSigner),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_019 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a1")
  @DisplayName("Test invalid OCSP response signature for TSL signer certificate")
  void verifyOcspResponseWithInvalidSignatureForTslSignerCert() {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.validSignature(false),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 4) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in past within tolerance")
  void verifyOcspResponseTslSignerCertProducedAtPastWithinTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 3) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in past out of tolerance")
  void verifyOcspResponseTslSignerCertProducedAtPastOutOfTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 2) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in future within tolerance")
  void verifyOcspResponseTslSignerCertProducedAtFutureWithinTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 1) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in future out of tolerance")
  void verifyOcspResponseTslSignerCertProducedAtFutureOutOfTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds()
            + 1000 * testSuiteConfig.getTestObject().getOcspGracePeriodSeconds();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_026 (Data Variant 2) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with thisUpdate in future within tolerance")
  void verifyOcspResponseTslSignerCertThisUpdateFutureWithinTolerance() {

    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_026 (Data Variant 1) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with thisUpdate in future out of tolerance")
  void verifyOcspResponseTslSignerCertThisUpdateFutureOutOfTolerance() {

    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_029 (Data Variant 2) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with nextUpdate in past within tolerance")
  void verifyOcspResponseTslSignerCertNextUpdatePastWithinTolerance() {

    initialState();

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_029 (Data Variant 1) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with nextUpdate in past out of tolerance")
  void verifyOcspResponseTslSignerCertNextUpdatePastOutOfTolerance() {

    initialState();

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        getDtoDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_034 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response of TSL signer certificate with missing nextUpdate")
  void verifyOcspResponseTslSignerCertMissingNextUpdate() {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.nextUpdateDeltaMilliseconds(null),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_024 */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6a")
  @MethodSource(
      "de.gematik.pki.pkits.testsuite.common.TestSuiteConstants#provideOcspResponseVariousStatusAndResponseBytes")
  @DisplayName(
      "Test various status of OCSP responses of TSL signer certificate with and without response"
          + " bytes")
  void verifyOcspResponseTslSignerCertVariousStatusAndResponseBytes(
      final OCSPRespStatus ocspRespStatus, final boolean withResponseBytes) {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.respStatus(ocspRespStatus).withResponseBytes(withResponseBytes),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_036 (Data Variant 1) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7b")
  @DisplayName("Test OCSP response of TSL signer certificate with missing CertHash")
  void verifyOcspResponseTslSignerCertMissingCertHash() {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.withCertHash(false),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_036 (Data Variant 2) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7c")
  @DisplayName("Test OCSP response of TSL signer certificate with invalid CertHash")
  void verifyOcspResponseTslSignerCertInvalidCertHash() {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.validCertHash(false),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_031 */
  @ParameterizedTest
  @EnumSource(
      value = CustomCertificateStatusType.class,
      names = {"UNKNOWN", "REVOKED"})
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 8b und 8c")
  @DisplayName("Test OCSP response of TSL signer certificate with status revoked and unknown")
  void verifyOcspResponseTslSignerCertStatusRevokedAndUnknown(
      final CustomCertificateStatusType customCertificateStatusType) {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder ->
            dtoBuilder.certificateStatus(
                CustomCertificateStatusDto.create(customCertificateStatusType)),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_022 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName("Test OCSP response of TSL signer certificate with responder id byName")
  void verifyOcspResponseTslSignerCertResponderIdByName() {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.responderIdType(ResponderIdType.BY_NAME),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_035 */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "RFC 5280", description = "4.1.1.2. signatureAlgorithm")
  @ValueSource(booleans = {true, false})
  @DisplayName("Test OCSP response of TSL signer certificate with null parameter in CertId")
  void verifyOcspResponseTslSignerCertWithNullParameterInCertId(
      final boolean withNullParameterHashAlgoOfCertId) {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder ->
            dtoBuilder.withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId),
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_021 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP check - step 4c")
  @DisplayName("Test OCSP response TSL signer certificate with timeout and delay")
  void verifyOcspResponseTslSignerCertTimeoutAndDelay() {

    initialState();

    final int longDelayMilliseconds = getLongTimeoutAndDelayFunc().apply(testSuiteConfig);
    final int shortDelayMilliseconds = getShortTimeoutAndDelayFunc().apply(testSuiteConfig);

    final int tslProcessingTimeSeconds =
        testSuiteConfig.getTestObject().getTslProcessingTimeSeconds();

    final int tslProcessingTimeSecondsNew =
        max(
            tslProcessingTimeSeconds,
            round((float) longDelayMilliseconds / 1000) + ocspSettings.getGracePeriodExtraDelay());

    testSuiteConfig.getTestObject().setTslProcessingTimeSeconds(tslProcessingTimeSecondsNew);

    try {
      log.info(
          "Starting data variant 1: long delayed ocsp response. Outside of specified value: {}ms.",
          longDelayMilliseconds);
      updateTrustStoreUsingOcspResponderConfig(
          CreateTslTemplate.alternativeTsl(),
          dtoBuilder -> dtoBuilder.delayMilliseconds(longDelayMilliseconds),
          TSL_UPDATE_NOT_EXPECTED,
          getPathOfAlternativeCertificate(),
          USECASE_INVALID);

      log.info(
          "Starting data variant 2: short delayed ocsp response. Inside specified value: {}ms.",
          shortDelayMilliseconds);
      updateTrustStoreUsingOcspResponderConfig(
          CreateTslTemplate.alternativeTsl(),
          dtoBuilder -> dtoBuilder.delayMilliseconds(shortDelayMilliseconds),
          TSL_UPDATE_EXPECTED,
          getPathOfAlternativeCertificate(),
          USECASE_VALID);
    } catch (final Exception e) {
      testSuiteConfig.getTestObject().setTslProcessingTimeSeconds(tslProcessingTimeSeconds);
      throw e;
    }
    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_016 */
  @ParameterizedTest
  @EnumSource(
      value = CertificateIdGeneration.class,
      names = {"VALID_CERTID"},
      mode = EnumSource.Mode.EXCLUDE)
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP check - step 6b")
  @DisplayName("Test invalid cert id in OCSP response for TSL signer cert")
  void verifyOcspResponseTslSignerCertInvalidCertId(
      final CertificateIdGeneration certificateIdGeneration) {

    initialState();

    updateTrustStoreUsingOcspResponderConfig(
        CreateTslTemplate.alternativeTsl(),
        dtoBuilder -> dtoBuilder.certificateIdGeneration(certificateIdGeneration),
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_011 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 3")
  @Afo(
      afoId = "GS-A_4650",
      description = "TUC_PKI_011: Prüfung des TSL-Signer-Zertifikates - Schritt 2")
  @Afo(afoId = "GS-A_4653", description = "TUC_PKI_002: Gültigkeitsprüfung des Zertifikats")
  @DisplayName("Test TSL signer certificate that is not yet valid - notBefore is in the future")
  void verifyTslSignerCertNotYetValid() {

    initialState();

    verifyForBadCertificateFromTrustAnchors(
        TslGenerator.tslSignerNotYetValid,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_DISABLED);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_012 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 3")
  @Afo(
      afoId = "GS-A_4650",
      description = "TUC_PKI_011: Prüfung des TSL-Signer-Zertifikates - Schritt 2")
  @Afo(afoId = "GS-A_4653", description = "TUC_PKI_002: Gültigkeitsprüfung des Zertifikats")
  @DisplayName("Test TSL signer certificate that is expired")
  void verifyTslSignerCertExpired() {

    initialState();

    verifyForBadCertificateFromTrustAnchors(
        TslGenerator.tslSignerExpired,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_DISABLED);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 3")
  @DisplayName("Test TSL signer certificate is broken")
  void verifyTslSignerCertBroken() {

    initialState();

    updateTrustStore(
        "Offer a TSL with alternative CAs (the TSL signer certificate contains an invalid ASN1"
            + " structure).",
        newTslGenerator("altCaAndTslSignerBrokenAsn1", new BreakSignerTslOperation())
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_DO_NOT_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  private void verifyForBadCertificateFromTrustAnchors(
      final Path tslBadSignerP12Path,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {

    final P12Container p12ContainerBad =
        P12Reader.getContentFromP12(tslBadSignerP12Path, tslSignerKeystorePassw);

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);
    final TslDownload tslDownload =
        newTslGenerator()
            .getTslDownloadWithTemplateAndSigner(
                offeredTslSeqNr,
                CreateTslTemplate.alternativeTsl(),
                p12ContainerBad,
                signerKeyUsageCheck,
                signerValidityCheck);

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(p12ContainerBad.getCertificate())
            .signer(defaultOcspSigner);

    tslDownload.configureOcspResponderForTslSigner(dtoBuilder);
    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSignerOptional();

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_INVALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_DO_NOT_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_013 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 3")
  @Afo(
      afoId = "GS-A_4650",
      description = "TUC_PKI_011: Prüfung des TSL-Signer-Zertifikates - Schritt 3")
  @DisplayName("Test TSL signer certificates with invalid key usage and extended key usage")
  void verifyTslSignerCertInvalidKeyUsageAndExtendedKeyUsage() {

    initialState();

    verifyForBadCertificateFromTrustAnchors(
        TslGenerator.tslSignerInvalidExtendedKeyusage,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);

    verifyForBadCertificateFromTrustAnchors(
        TslGenerator.tslSignerInvalidKeyusage,
        SIGNER_KEY_USAGE_CHECK_DISABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_004 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 3")
  @Afo(
      afoId = "GS-A_4650",
      description = "TUC_PKI_011: Prüfung des TSL-Signer-Zertifikates - Schritt 5")
  @DisplayName("Invalid signature of the TSL signer certificate.")
  void verifyForInvalidSignatureOfTslSigner() {

    initialState();

    final P12Container p12ContainerInvalidSig =
        P12Reader.getContentFromP12(
            TslGenerator.invalideSignatureSignerPath, tslSignerKeystorePassw);

    /* TSLTypeID 522 */
    updateTrustStore(
        "Offer a TSL with alternate CAs.",
        newTslGenerator("invalidSignerSignatureAlternativeCA")
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl(), p12ContainerInvalidSig),
        OCSP_REQUEST_IGNORE,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    establishDefaultTrustStoreAndExecuteUseCase();
  }
}
