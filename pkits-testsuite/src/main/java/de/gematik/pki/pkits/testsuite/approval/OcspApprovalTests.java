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

import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_PRECONFIGURED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusType;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.OcspResponderConfigDtoBuilder;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI OCSP approval tests.")
@Order(1)
class OcspApprovalTests extends ApprovalTestsBase {

  private static final TestInfo SKIP_INITIAL_STATE = null;

  void verifyWithConfiguredOcspResponder(
      final TestInfo testInfo,
      final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep,
      final UseCaseResult useCaseResult) {

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, useCaseResult, OCSP_REQUEST_EXPECT);
  }

  void verifyWithConfiguredOcspResponder(
      final TestInfo testInfo,
      final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep,
      final UseCaseResult useCaseResult,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {

    if (testInfo != null) {
      testCaseMessage(testInfo);
      initialState();
    }

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(defaultOcspSigner);

    dtoBuilderStep.accept(dtoBuilder);

    final OcspResponderConfigDto dto = dtoBuilder.build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(
        certPath, useCaseResult, OCSP_RESP_PRECONFIGURED, ocspRequestExpectationBehaviour);
  }

  /** gematikId: UE_PKI_TS_0302_024 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 1")
  @DisplayName("Test OCSP grace period")
  void verifyOcspGracePeriod(final TestInfo testInfo) {

    verifyWithConfiguredOcspResponder(
        testInfo,
        dtoBuilder -> dtoBuilder.certificateStatus(CustomCertificateStatusDto.createUnknown()),
        USECASE_INVALID);

    verifyWithConfiguredOcspResponder(SKIP_INITIAL_STATE, dtoBuilder -> {}, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_017 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 4c")
  @DisplayName("Test OCSP response with timeout and delay")
  void verifyOcspResponseTimeoutAndDelay(final TestInfo testInfo) {

    final int shortDelayMilliseconds = getShortTimeoutAndDelayFunc().apply(testSuiteConfig);

    verifyWithConfiguredOcspResponder(
        testInfo,
        dtoBuilder -> dtoBuilder.delayMilliseconds(shortDelayMilliseconds),
        USECASE_VALID);

    final int longDelayMilliseconds = getLongTimeoutAndDelayFunc().apply(testSuiteConfig);

    verifyWithConfiguredOcspResponder(
        SKIP_INITIAL_STATE,
        dtoBuilder -> dtoBuilder.delayMilliseconds(longDelayMilliseconds),
        USECASE_INVALID,
        OCSP_REQUEST_DO_NOT_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_014 */
  @ParameterizedTest
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a")
  @DisplayName("Test missing OCSP signer in TSL")
  @ValueSource(
      strings = {
        TestSuiteConstants.OCSP_SIGNER_NOT_IN_TSL_FILENAME,
        TestSuiteConstants.OCSP_SIGNER_DIFFERENT_KEY
      })
  void verifyMissingOcspSignerInTslForUseCaseCertificate(
      final String signerFilename, final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final P12Container ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(signerFilename),
            ocspSettings.getSignerPassword());

    verifyWithConfiguredOcspResponder(
        testInfo, dtoBuilder -> dtoBuilder.signer(ocspSigner), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_015 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a1")
  @DisplayName("Test invalid signature in OCSP response")
  void verifyInvalidSignatureInOcspResponse(final TestInfo testInfo) {

    verifyWithConfiguredOcspResponder(
        testInfo, dtoBuilder -> dtoBuilder.validSignature(false), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in past within tolerance")
  void verifyOcspResponseProducedAtPastWithinTolerance(final TestInfo testInfo) {

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in past out of tolerance")
  void verifyOcspResponseProducedAtPastOutOfTolerance(final TestInfo testInfo) {

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);
    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in future within tolerance")
  void verifyOcspResponseProducedAtFutureWithinTolerance(final TestInfo testInfo) {

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_VALID);

    // WARNING: if this test case fails, we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in future out of tolerance")
  void verifyOcspResponseProducedAtFutureOutOfTolerance(final TestInfo testInfo) {

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_INVALID);
    // WARNING: if this test case fails, we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_022 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with thisUpdate in future within tolerance")
  void verifyOcspResponseThisUpdateFutureWithinTolerance(final TestInfo testInfo) {

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_VALID);

    // WARNING: if this test case fails, we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_022 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with thisUpdate in future out of tolerance")
  void verifyOcspResponseThisUpdateFutureOutOfTolerance(final TestInfo testInfo) {

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_INVALID);

    // WARNING: if this test case fails, we do not wait -- all the following test cases can be
    // influenced
    //   verifyOcspResponseProducedAtFutureOutOfTolerance
    //   verifyOcspResponseProducedAtFutureWithinTolerance
    //   verifyOcspResponseThisUpdateFutureOutOfTolerance
    //   verifyOcspResponseThisUpdateFutureWithinTolerance

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TS_0302_032 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with nextUpdate in past within tolerance")
  void verifyOcspResponseNextUpdatePastWithinTolerance(final TestInfo testInfo) {

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds);
    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_032 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with nextUpdate in past out of tolerance")
  void verifyOcspResponseNextUpdatePastOutOfTolerance(final TestInfo testInfo) {

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigDtoBuilder> dtoBuilderStep =
        getDtoDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(testInfo, dtoBuilderStep, USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_031 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with missing nextUpdate")
  void verifyOcspResponseMissingNextUpdate(final TestInfo testInfo) {
    verifyWithConfiguredOcspResponder(
        testInfo, dtoBuilder -> dtoBuilder.nextUpdateDeltaMilliseconds(null), USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_020 */
  @ParameterizedTest
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6a")
  @MethodSource(
      "de.gematik.pki.pkits.testsuite.common.TestSuiteConstants#provideOcspResponseVariousStatusAndResponseBytes")
  @DisplayName("Test various status of OCSP responses with and without response bytes")
  void verifyOcspResponseVariousStatusAndResponseBytes(
      final OCSPRespStatus ocspRespStatus,
      final boolean withResponseBytes,
      final TestInfo testInfo) {

    verifyWithConfiguredOcspResponder(
        testInfo,
        dtoBuilder -> dtoBuilder.respStatus(ocspRespStatus).withResponseBytes(withResponseBytes),
        USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_012 */
  @ParameterizedTest
  @EnumSource(
      value = CertificateIdGeneration.class,
      names = {"VALID_CERTID"},
      mode = EnumSource.Mode.EXCLUDE)
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6b")
  @DisplayName("Test invalid cert id in OCSP response")
  void verifyInvalidCerIdInOcspResponse(
      final CertificateIdGeneration certificateIdGeneration, final TestInfo testInfo) {

    verifyWithConfiguredOcspResponder(
        testInfo,
        dtoBuilder -> dtoBuilder.certificateIdGeneration(certificateIdGeneration),
        USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_046 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7b")
  @DisplayName("Test missing CertHash in OCSP response")
  void verifyMissingCertHashInOcspResponse(final TestInfo testInfo) {
    verifyWithConfiguredOcspResponder(
        testInfo, dtoBuilder -> dtoBuilder.withCertHash(false), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_046 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7c")
  @DisplayName("Test invalid CertHash in OCSP response")
  void verifyInvalidCertHashInOcspResponse(final TestInfo testInfo) {
    verifyWithConfiguredOcspResponder(
        testInfo, dtoBuilder -> dtoBuilder.validCertHash(false), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_027 */
  @ParameterizedTest
  @EnumSource(
      value = CustomCertificateStatusType.class,
      names = {"UNKNOWN", "REVOKED"})
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 8b und 8c")
  @DisplayName("Test OCSP response with certificate status revoked and unknown")
  void verifyOcspCertificateStatusRevokedAndUnknown(
      final CustomCertificateStatusType customCertificateStatusType, final TestInfo testInfo) {

    verifyWithConfiguredOcspResponder(
        testInfo,
        dtoBuilder ->
            dtoBuilder.certificateStatus(
                CustomCertificateStatusDto.create(customCertificateStatusType)),
        USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_035 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 2")
  @Afo(
      afoId = "GS-A_4656",
      description = "TUC_PKI_005: Adresse für Status- und Sperrprüfung ermitteln - Schritt 2b")
  @DisplayName("CA certificate in TSL without ServiceSupplyPoint.")
  void verifyForCaCertificateWithoutServiceSupplyPoint(final TestInfo testInfo) {
    testCaseMessage(testInfo);
    initialState();

    final TslOperation deleteSsps =
        tslContainer -> {
          final byte[] tslBytes = tslContainer.getAsTslBytes();

          final X509Certificate cert =
              CertReader.getX509FromP12(getPathOfAlternativeCertificate(), clientKeystorePassw);
          try {
            final byte[] newTslBytes =
                TslModifier.deleteSspsForCAsOfEndEntity(tslBytes, cert, "PkiTestSuite");

            return newTslGenerator().signTslOperation(defaultTslSigner).apply(newTslBytes);

          } catch (final GemPkiException e) {
            throw new TestSuiteException(e);
          }
        };
    updateTrustStore(
        "Offer a TSL with alternative CAs without ServiceSupplyPoints.",
        newTslGenerator("noServiceSupplyPoints", deleteSsps)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_001 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 2")
  @Afo(
      afoId = "GS-A_4656",
      description = "TUC_PKI_005: Adresse für Status- und Sperrprüfung ermitteln - Schritt 2b")
  @Afo(afoId = "TODO - GS-A_4654", description = "TUC_PKI_003: CA-Zertifikat finden - Schritt 2b")
  @DisplayName(
      "NOT IMPLEMENTED YET - CA certificate is not included in TSL (for nonQES certificate).")
  @Disabled("NOT IMPLEMENTED YET")
  void verifyForCaCertificateIsNotInTsl(final TestInfo testInfo) {
    failNotImplemented();
  }

  /** gematikId: UE_PKI_TS_0302_018 */
  @Test
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName("Test OCSP response with responder id byName")
  void verifyOcspResponseResponderIdByName(final TestInfo testInfo) {
    verifyWithConfiguredOcspResponder(
        testInfo, dtoBuilder -> dtoBuilder.responderIdType(ResponderIdType.BY_NAME), USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_045 */
  @ParameterizedTest
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @Afo(afoId = "RFC 5280", description = "4.1.1.2. signatureAlgorithm")
  @ValueSource(booleans = {true, false})
  @DisplayName("Test OCSP response with null parameter in CertId")
  void verifyOcspResponseWithNullParameterInCertId(
      final boolean withNullParameterHashAlgoOfCertId, final TestInfo testInfo) {
    verifyWithConfiguredOcspResponder(
        testInfo,
        dtoBuilder ->
            dtoBuilder.withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId),
        USECASE_VALID);
  }
}
