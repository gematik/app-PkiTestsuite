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
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TSL_SIGNER;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.KEYSTORE_PASSWORD;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.ALTERNATIVE_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.DEFAULT_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTests.TslUpdateExpectation.TSL_UPDATE_EXPECTED;
import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTests.TslUpdateExpectation.TSL_UPDATE_NOT_EXPECTED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_DISABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_DISABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;
import static java.lang.Integer.max;
import static java.lang.Math.round;

import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusType;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslDownloadGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.BreakSignerTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
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

  private void updateTrustStoreWithAlternativeCerts(
      final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoDateConfigurer,
      final TslUpdateExpectation tslUpdateExpected,
      final UseCaseResult useCaseResult) {

    final CertificateDto.CertificateDtoBuilder certificateDtoBuilder =
        CertificateDto.builder()
            .eeCert(DEFAULT_TSL_SIGNER.getCertificate())
            .issuerCert(DEFAULT_TRUST_ANCHOR)
            .signer(DEFAULT_OCSP_SIGNER);

    certificateDtoDateConfigurer.accept(certificateDtoBuilder);

    log.info(
        "START updateTrustStoreWithAlternativeCerts - {}", PkitsTestSuiteUtils.getCallerTrace());
    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);

    final TrustStatusListType tsl = CreateTslTemplate.alternativeTsl(eccOnly);
    final TslDownload tslDownload =
        newTslDownloadGenerator("updateTrustStoreWithAlternativeCerts").getStandardTslDownload(tsl);

    tslDownload.configureOcspResponderForTslSigner(
        OcspResponderConfig.builder()
            .certificateDtos(List.of(certificateDtoBuilder.build()))
            .build());
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
        getPathOfAlternativeClientCert(),
        getPathOfAlternativeIssuerCert(),
        useCaseResult,
        OCSP_RESP_WITH_PROVIDED_CERT,
        ocspRequestExpectationBehaviour);
    log.info("END updateTrustStoreWithAlternativeCerts - {}", PkitsTestSuiteUtils.getCallerTrace());
  }

  /** gematikId: UE_PKI_TC_0105_018 */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a")
  @DisplayName("Test missing OCSP signer in TSL for TSL signer certificate")
  @MethodSource(
      "de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils#provideForMissingOcspSigner")
  void verifyMissingOcspSignerInTslForTslSignerCert(final P12Container ocspSigner) {

    initialState();

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.signer(ocspSigner), TSL_UPDATE_NOT_EXPECTED, USECASE_INVALID);

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

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.validSignature(false), TSL_UPDATE_NOT_EXPECTED, USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_034 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName("Test OCSP response of TSL signer certificate with missing nextUpdate")
  void verifyOcspResponseTslSignerCertMissingNextUpdate() {

    initialState();

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.nextUpdateDeltaMilliseconds(null),
        TSL_UPDATE_EXPECTED,
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
      "de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils#provideOcspResponseVariousStatusAndResponseBytes")
  @DisplayName(
      "Test various status of OCSP responses of TSL signer certificate with and without response"
          + " bytes")
  void verifyOcspResponseTslSignerCertVariousStatusAndResponseBytes(
      final OCSPRespStatus ocspRespStatus, final boolean withResponseBytes) {

    initialState();

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.respStatus(ocspRespStatus).withResponseBytes(withResponseBytes),
        TSL_UPDATE_NOT_EXPECTED,
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

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.withCertHash(false), TSL_UPDATE_NOT_EXPECTED, USECASE_INVALID);

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

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.validCertHash(false), TSL_UPDATE_NOT_EXPECTED, USECASE_INVALID);

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

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder ->
            dtoBuilder.certificateStatus(
                CustomCertificateStatusDto.create(customCertificateStatusType)),
        TSL_UPDATE_NOT_EXPECTED,
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

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.responderIdType(ResponderIdType.BY_NAME),
        TSL_UPDATE_EXPECTED,
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

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder ->
            dtoBuilder.withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId),
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_021 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 4c")
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
      updateTrustStoreWithAlternativeCerts(
          dtoBuilder -> dtoBuilder.delayMilliseconds(longDelayMilliseconds),
          TSL_UPDATE_NOT_EXPECTED,
          USECASE_INVALID);

      log.info(
          "Starting data variant 2: short delayed ocsp response. Inside specified value: {}ms.",
          shortDelayMilliseconds);
      updateTrustStoreWithAlternativeCerts(
          dtoBuilder -> dtoBuilder.delayMilliseconds(shortDelayMilliseconds),
          TSL_UPDATE_EXPECTED,
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
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6b")
  @DisplayName("Test invalid cert id in OCSP response for TSL signer cert")
  void verifyOcspResponseTslSignerCertInvalidCertId(
      final CertificateIdGeneration certificateIdGeneration) {

    initialState();

    updateTrustStoreWithAlternativeCerts(
        dtoBuilder -> dtoBuilder.certificateIdGeneration(certificateIdGeneration),
        TSL_UPDATE_NOT_EXPECTED,
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
        TslDownloadGenerator.tslSignerNotYetValid,
        DEFAULT_TRUST_ANCHOR,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_DISABLED);

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
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
        TslDownloadGenerator.tslSignerExpired,
        DEFAULT_TRUST_ANCHOR,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_DISABLED);

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
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
        newTslDownloadGenerator("altCaAndTslSignerBrokenAsn1", new BreakSignerTslOperation())
            .getStandardTslDownload(CreateTslTemplate.alternativeTsl(eccOnly)),
        OCSP_REQUEST_DO_NOT_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  private void verifyForBadCertificateFromTrustAnchors(
      final Path tslBadSignerP12Path,
      final X509Certificate trustAnchor,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {

    final P12Container p12ContainerBad =
        P12Reader.getContentFromP12(tslBadSignerP12Path, KEYSTORE_PASSWORD);

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);
    final TslDownload tslDownload =
        newTslDownloadGenerator()
            .getTslDownloadWithTemplateAndSigner(
                offeredTslSeqNr,
                CreateTslTemplate.alternativeTsl(eccOnly),
                p12ContainerBad,
                trustAnchor,
                signerKeyUsageCheck,
                signerValidityCheck);

    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(p12ContainerBad.getCertificate())
                        .issuerCert(trustAnchor)
                        .signer(DEFAULT_OCSP_SIGNER)
                        .build()))
            .build();

    tslDownload.configureOcspResponderForTslSigner(ocspResponderConfig);
    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSignerOptional();

    useCaseWithCert(
        ALTERNATIVE_CLIENT_CERTS_CONFIG,
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
        TslDownloadGenerator.tslSignerInvalidExtendedKeyusage,
        DEFAULT_TRUST_ANCHOR,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);

    verifyForBadCertificateFromTrustAnchors(
        TslDownloadGenerator.tslSignerInvalidKeyusage,
        DEFAULT_TRUST_ANCHOR,
        SIGNER_KEY_USAGE_CHECK_DISABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);

    useCaseWithCert(
        DEFAULT_CLIENT_CERTS_CONFIG,
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
  @Afo(
      afoId = "GS-A_4655",
      description = "TUC_PKI_004: Mathematische Prüfung der Zertifikatssignatur")
  @DisplayName("Invalid signature of the TSL signer certificate.")
  void verifyForInvalidSignatureOfTslSigner() {

    initialState();

    final P12Container p12ContainerInvalidSig =
        P12Reader.getContentFromP12(
            TslDownloadGenerator.invalideSignatureSignerPath, KEYSTORE_PASSWORD);

    /* TSLTypeID 522 */
    updateTrustStore(
        "Offer a TSL with alternate CAs.",
        newTslDownloadGenerator("invalidSignerSignatureAlternativeCA")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTsl(eccOnly),
                p12ContainerInvalidSig,
                DEFAULT_TRUST_ANCHOR),
        OCSP_REQUEST_IGNORE,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, USECASE_INVALID));

    establishDefaultTrustStoreAndExecuteUseCase();
  }
}
