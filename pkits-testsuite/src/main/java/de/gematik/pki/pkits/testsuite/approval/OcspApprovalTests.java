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

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_OCSP_SIGNER;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TSL_SIGNER;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.KEYSTORE_PASSWORD;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.ALTERNATIVE_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.DEFAULT_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_PRECONFIGURED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponseAlgoBehavior;
import de.gematik.pki.gemlibpki.ocsp.OcspUtils;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusType;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig.OcspResponderConfigBuilder;
import de.gematik.pki.pkits.testsuite.common.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslDownloadGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.usecases.UseCase;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.Req;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI OCSP approval tests.")
@Order(1)
class OcspApprovalTests extends ApprovalTestsBase {
  private static final boolean SKIP_INITIAL_STATE = false;

  void verifyWithConfiguredOcspResponder(
      final Consumer<OcspResponderConfigBuilder> configBuilderStep,
      final UseCaseResult useCaseResult) {

    verifyWithConfiguredOcspResponder(true, configBuilderStep, useCaseResult);
  }

  void configureOcspResponder(final Consumer<OcspResponderConfigBuilder> configBuilderStep) {

    final Path eeCertPath = getPathOfDefaultClientCert();

    final OcspResponderConfigBuilder configBuilder =
        OcspResponderConfig.builder()
            .eeCert(CertReader.getX509FromP12(eeCertPath, KEYSTORE_PASSWORD))
            .issuerCert(
                CertReader.readX509(
                    DEFAULT_CLIENT_CERTS_CONFIG.getIssuerCertPathFunc().apply(this)))
            .signer(DEFAULT_OCSP_SIGNER);

    configBuilderStep.accept(configBuilder);

    final OcspResponderConfig config = configBuilder.build();

    TestEnvironment.configureOcspResponder(ocspResponderUri, config);
  }

  void verifyWithConfiguredOcspResponder(
      final boolean executeInitialState,
      final Consumer<OcspResponderConfigBuilder> configBuilderStep,
      final UseCaseResult useCaseResult) {

    if (executeInitialState) {
      initialState();
    }

    configureOcspResponder(configBuilderStep);

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG, useCaseResult, OCSP_RESP_PRECONFIGURED, OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_024 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 1")
  @DisplayName("Test OCSP grace period")
  void verifyOcspGracePeriod() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.certificateStatus(CustomCertificateStatusDto.createUnknown()),
        USECASE_INVALID);

    verifyWithConfiguredOcspResponder(SKIP_INITIAL_STATE, dtoBuilder -> {}, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_017 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 4c")
  @DisplayName("Test OCSP response with timeout and delay")
  void verifyOcspResponseTimeoutAndDelay() {

    final int shortDelayMilliseconds = getShortTimeoutAndDelayFunc().apply(testSuiteConfig);

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.delayMilliseconds(shortDelayMilliseconds), USECASE_VALID);

    final int longDelayMilliseconds = getLongTimeoutAndDelayFunc().apply(testSuiteConfig);

    verifyWithConfiguredOcspResponder(
        SKIP_INITIAL_STATE,
        dtoBuilder -> dtoBuilder.delayMilliseconds(longDelayMilliseconds),
        USECASE_INVALID);

    PkitsCommonUtils.waitMilliseconds(
        longDelayMilliseconds
            - testSuiteConfig.getTestObject().getOcspTimeoutSeconds() * 1000L
            + testSuiteConfig.getTestObject().getOcspProcessingTimeSeconds() * 1000L);
  }

  /** gematikId: UE_PKI_TS_0302_014 */
  @ParameterizedTest
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a")
  @DisplayName("Test missing OCSP signer in TSL")
  @MethodSource(
      "de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils#provideForMissingOcspSigner")
  void verifyMissingOcspSignerInTslForUseCaseCertificate(final P12Container ocspSigner) {
    verifyWithConfiguredOcspResponder(dtoBuilder -> dtoBuilder.signer(ocspSigner), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_015 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a1")
  @DisplayName("Test invalid signature in OCSP response")
  void verifyInvalidSignatureInOcspResponse() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.validSignature(false), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in past within tolerance")
  void verifyOcspResponseProducedAtPastWithinTolerance() {

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in past out of tolerance")
  void verifyOcspResponseProducedAtPastOutOfTolerance() {

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_021 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in future within tolerance")
  void verifyOcspResponseProducedAtFutureWithinTolerance() {

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_VALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with producedAt in future out of tolerance")
  void verifyOcspResponseProducedAtFutureOutOfTolerance() {

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_INVALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with thisUpdate in future within tolerance")
  void verifyOcspResponseThisUpdateFutureWithinTolerance() {

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_VALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with thisUpdate in future out of tolerance")
  void verifyOcspResponseThisUpdateFutureOutOfTolerance() {

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_INVALID);

    // NOTE: if this test case fails, and we do not wait -- all the following test cases can be
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with nextUpdate in past within tolerance")
  void verifyOcspResponseNextUpdatePastWithinTolerance() {

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_032 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with nextUpdate in past out of tolerance")
  void verifyOcspResponseNextUpdatePastOutOfTolerance() {

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    final Consumer<OcspResponderConfigBuilder> configBuilderStep =
        getDateConfigStep(DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds);

    verifyWithConfiguredOcspResponder(configBuilderStep, USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_031 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response with missing nextUpdate")
  void verifyOcspResponseMissingNextUpdate() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.nextUpdateDeltaMilliseconds(null), USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_020 */
  @ParameterizedTest
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6a")
  @MethodSource(
      "de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils#provideOcspResponseVariousStatusAndResponseBytes")
  @DisplayName("Test various status of OCSP responses with and without response bytes")
  void verifyOcspResponseVariousStatusAndResponseBytes(
      final OCSPRespStatus ocspRespStatus, final boolean withResponseBytes) {

    verifyWithConfiguredOcspResponder(
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
  void verifyInvalidCerIdInOcspResponse(final CertificateIdGeneration certificateIdGeneration) {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.certificateIdGeneration(certificateIdGeneration), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_046 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7b")
  @DisplayName("Test missing CertHash in OCSP response")
  void verifyMissingCertHashInOcspResponse() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.withCertHash(false), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_046 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7c")
  @DisplayName("Test invalid CertHash in OCSP response")
  void verifyInvalidCertHashInOcspResponse() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.validCertHash(false), USECASE_INVALID);
  }

  /** gematikId: UE_PKI_TS_0302_027 */
  @ParameterizedTest
  @EnumSource(
      value = CustomCertificateStatusType.class,
      names = {"UNKNOWN", "REVOKED"})
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 8b und 8c")
  @DisplayName("Test OCSP response with certificate status revoked and unknown")
  void verifyOcspCertificateStatusRevokedAndUnknown(
      final CustomCertificateStatusType customCertificateStatusType) {

    verifyWithConfiguredOcspResponder(
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
  @DisplayName("CA certificate in TSL without ServiceSupplyPoint")
  void verifyForCaCertificateWithoutServiceSupplyPoint() {

    initialState();

    final TslOperation deleteSsps =
        tslContainer -> {
          final byte[] tslBytesUnsigned = tslContainer.getAsTslUnsignedBytes();

          final X509Certificate cert =
              CertReader.getX509FromP12(getPathOfAlternativeClientCert(), KEYSTORE_PASSWORD);
          try {
            final byte[] newTslUnsignedBytes =
                TslModifier.deleteSspsForCAsOfEndEntity(tslBytesUnsigned, cert, "PkiTestSuite");

            return newTslDownloadGenerator()
                .signTslOperation(DEFAULT_TSL_SIGNER)
                .apply(newTslUnsignedBytes);

          } catch (final GemPkiException e) {
            throw new TestSuiteException(e);
          }
        };

    updateTrustStore(
        "Offer a TSL with alternative CAs without ServiceSupplyPoints.",
        newTslDownloadGenerator("noServiceSupplyPoints", deleteSsps)
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TS_0302_018 */
  @Test
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName("Test OCSP response with responder id byName")
  void verifyOcspResponseResponderIdByName() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.responderIdType(ResponderIdType.BY_NAME), USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_045 */
  @ParameterizedTest
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @Afo(afoId = "RFC 5280", description = "4.1.1.2. signatureAlgorithm")
  @ValueSource(booleans = {true, false})
  @DisplayName("Test OCSP response with null parameter in CertId")
  void verifyOcspResponseWithNullParameterInCertId(
      final boolean withNullParameterHashAlgoOfCertId) {

    verifyWithConfiguredOcspResponder(
        dtoBuilder ->
            dtoBuilder.withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId),
        USECASE_VALID);
  }

  protected void verifyOcspReq(
      final OCSPReq ocspReq, final X509Certificate eeCert, final X509Certificate eeIssuerCert)
      throws CertificateEncodingException {

    final Req[] reqList = ocspReq.getRequestList();

    assertThat(reqList).as("Number of elements in reqList is not 1!").hasSize(1);

    assertThat(ocspReq.getVersionNumber()).as("Version of ocspReq is not 1!").isEqualTo(1);

    // ---------------------------

    final Req singleReq = reqList[0];
    final CertificateID reqCertId = singleReq.getCertID();
    final String hashAlgoId = reqCertId.getHashAlgOID().getId();

    final String sha1AlgoId = OIWObjectIdentifiers.idSHA1.getId();
    final String sha256AlgoId = NISTObjectIdentifiers.id_sha256.getId();

    final List<String> allowedHashes = List.of(sha1AlgoId, sha256AlgoId);

    assertThat(allowedHashes.toArray())
        .as("Hash algorithm of ocspReq is not SHA1 or SHA256!")
        .contains(hashAlgoId);

    // ---------------------------

    final byte[] certIssuerNameHash =
        GemLibPkiUtils.calculateSha1(eeIssuerCert.getSubjectX500Principal().getEncoded());
    final byte[] reqIssuerNameHash = reqCertId.getIssuerNameHash();

    assertThat(certIssuerNameHash)
        .as("Values of issuerNameHash from ocspReq and certificate does not match!")
        .isEqualTo(reqIssuerNameHash);

    // ---------------------------

    final byte[] publicKeyBytes =
        new JcaX509CertificateHolder(eeIssuerCert)
            .getSubjectPublicKeyInfo()
            .getPublicKeyData()
            .getBytes();

    final byte[] certIssuerKeyHash = GemLibPkiUtils.calculateSha1(publicKeyBytes);
    final byte[] reqIssuerKeyHash = reqCertId.getIssuerKeyHash();

    assertThat(certIssuerKeyHash)
        .as("Values of issuerKeyHash from ocspReq and certificate does not match!")
        .isEqualTo(reqIssuerKeyHash);

    // ---------------------------

    assertThat(eeCert.getSerialNumber())
        .as("Values of certSerialNr from ocspReq and certificate does not match!")
        .isEqualTo(reqCertId.getSerialNumber());

    // ---------------------------

    log.info(
        "finished checking: requestList - size 1, OCSPVersion == 1, hashAlgorithm = SHA-1; compared"
            + " against cert: issuerNameHash, issuerKeyHash, certSerialNr");
  }

  private TslDownload updateDefaultTrustStore() {
    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);
    final TslDownload tslDownload =
        newTslDownloadGenerator(TslDownloadGenerator.TSL_NAME_DEFAULT)
            .getStandardTslDownload(CreateTslTemplate.defaultTsl());

    tslDownload.configureOcspResponderForTslSigner();
    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForTslSigner(tslSequenceNr.getExpectedNrInTestObject());

    tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);
    return tslDownload;
  }

  private X509Certificate getIssuerCert(final X509Certificate eeCert, final TrustStatusListType tsl)
      throws GemPkiException {

    final TslInformationProvider tslInformationProvider = new TslInformationProvider(tsl);

    final List<TspService> filteredTspServices =
        tslInformationProvider.getFilteredTspServices(List.of(TslConstants.STI_PKC));

    final TspInformationProvider tspInformationProvider =
        new TspInformationProvider(filteredTspServices, "Testsuite");

    return tspInformationProvider.getIssuerTspServiceSubset(eeCert).getX509IssuerCert();
  }

  private void verifyOcspRequestStructureFromTslUpdate(final TslDownload tslDownload)
      throws IOException, GemPkiException, CertificateEncodingException {

    final byte[] ocspReqBytes =
        tslDownload.getOcspRequestHistoryContainer().getHistoryEntries().get(0).getOcspReqBytes();
    final OCSPReq ocspReq = new OCSPReq(ocspReqBytes);

    final X509Certificate eeCert = tslDownload.getTslSignerCert();
    final X509Certificate eeIssuerCert = getIssuerCert(eeCert, tslDownload.getTslUnsigned());

    verifyOcspReq(ocspReq, eeCert, eeIssuerCert);
  }

  void verifyOcspRequestStructureFromUseCase(final TslDownload tslDownload)
      throws IOException, GemPkiException, CertificateEncodingException {

    final X509Certificate eeCert =
        CertReader.getX509FromP12(getPathOfDefaultClientCert(), KEYSTORE_PASSWORD);
    final X509Certificate issuerCert =
        CertReader.readX509(DEFAULT_CLIENT_CERTS_CONFIG.getIssuerCertPathFunc().apply(this));

    configureOcspResponder(eeCert, issuerCert);
    waitForOcspCacheToExpire();
    assertThat(UseCase.exec(getPathOfDefaultClientCert(), testSuiteConfig))
        .as(USECASE_VALID.getMessage())
        .isEqualTo(USECASE_VALID.getExpectedReturnCode());

    final byte[] ocspReqBytes =
        OcspResponderManager.getOcspHistoryPart(
                ocspResponderUri,
                tslSequenceNr.getExpectedNrInTestObject(),
                eeCert.getSerialNumber())
            .get(0)
            .getOcspReqBytes();

    final OCSPReq ocspReq = new OCSPReq(ocspReqBytes);

    final X509Certificate eeIssuerCert = getIssuerCert(eeCert, tslDownload.getTslUnsigned());

    verifyOcspReq(ocspReq, eeCert, eeIssuerCert);
  }

  /** gematikId: UE_PKI_TC_0105_032, UE_PKI_TS_0302_028 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Anmerkungen")
  @Afo(afoId = "GS-A_4674", description = "OCSP-Requests gemäß Standards")
  @Afo(afoId = "RFC 6960", description = "4.1.1. ASN.1 Specification of the OCSP Request")
  @Afo(afoId = "RFC 5019", description = "2.1.1. OCSPRequest Structure")
  @DisplayName("Test OCSP request structure")
  void verifyOcspRequestStructure()
      throws IOException, GemPkiException, CertificateEncodingException {

    initialState();

    final TslDownload tslDownload = updateDefaultTrustStore();

    verifyOcspRequestStructureFromTslUpdate(tslDownload);

    verifyOcspRequestStructureFromUseCase(tslDownload);

    // NOTE: to be sure the TSL is imported correctly and current and expected tslSeqNr are handled
    // internally
    useCaseWithCert(
        ClientCertsConfig.DEFAULT_CLIENT_CERTS_CONFIG,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  private void executeValidUseCase() {

    waitForOcspCacheToExpire();

    configureOcspResponder(
        dtoBuilder -> dtoBuilder.responseAlgoBehavior(ResponseAlgoBehavior.MIRRORING));

    final UseCaseResult useCaseResult = USECASE_VALID;
    final String message = "\"%s\" for %s%n".formatted(useCaseResult.getMessage(), currentTestInfo);

    final int useCaseReturnCode = UseCase.exec(getPathOfDefaultClientCert(), testSuiteConfig);
    assertThat(useCaseReturnCode).as(message).isEqualTo(useCaseResult.getExpectedReturnCode());
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage")
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName("Test OCSP response with SHA1 used for the certId.")
  void verifyHashAlgorithmsInOcspSha1() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.responseAlgoBehavior(ResponseAlgoBehavior.SHA1), USECASE_VALID);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage")
  @Afo(afoId = "GS-A_4674", description = "OCSP-Requests gemäß Standards")
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @Afo(afoId = "RFC 5754", description = "2.2. SHA-256")
  @DisplayName("Test OCSP Responses with SHA1 used for the certId.")
  @Disabled(
      "will be activated after the specification is updated to use SHA256 as default algorithm")
  void verifyHashAlgorithmsInOcspSha2() {

    verifyWithConfiguredOcspResponder(
        dtoBuilder -> dtoBuilder.responseAlgoBehavior(ResponseAlgoBehavior.SHA2), USECASE_VALID);
  }

  /** gematikId: UE_PKI_TS_0302_028 */
  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage")
  @Afo(afoId = "GS-A_4674", description = "OCSP-Requests gemäß Standards")
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName(
      "Test that the test object understands OCSP responses with the same hash algorithm it uses"
          + " for its requests in the certId.")
  void verifyHashAlgorithmsInOcspShaVersion() throws IOException {

    initialState();

    executeValidUseCase();

    final BigInteger certSerial =
        CertReader.getX509FromP12(getPathOfDefaultClientCert(), KEYSTORE_PASSWORD)
            .getSerialNumber();

    final List<OcspRequestHistoryEntryDto> historyEntries =
        OcspResponderManager.getOcspHistoryPart(
            ocspResponderUri, tslSequenceNr.getExpectedNrInTestObject(), certSerial);

    assertThat(historyEntries).isNotEmpty();
    final OcspRequestHistoryEntryDto historyEntry = historyEntries.get(0);

    final OCSPReq ocspReq = new OCSPReq(historyEntry.getOcspReqBytes());
    final Req singleReq = OcspUtils.getFirstSingleReq(ocspReq);
    final ASN1ObjectIdentifier algoId = singleReq.getCertID().getHashAlgOID();

    if (OIWObjectIdentifiers.idSHA1.equals(algoId)) {
      return;
    }

    if (NISTObjectIdentifiers.id_sha256.equals(algoId)) {
      return;
    }

    Assertions.fail(
        "Only SHA1 (%s) and SHA2 (%s) algorithms are allowed in OCSP request, but %s was used.",
        OIWObjectIdentifiers.idSHA1.getId(),
        NISTObjectIdentifiers.id_sha256.getId(),
        algoId.getId());
  }
}
