/*
 * Copyright 2024 gematik GmbH
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
import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTests.TslUpdateExpectation.TSL_UPDATE_EXPECTED;
import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTests.TslUpdateExpectation.TSL_UPDATE_NOT_EXPECTED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.common.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestObjectConfig;
import de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.List;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
@DisplayName("PKI TSL signer tolerance approval tests.")
@Order(1)
class TslSignerToleranceApprovalTests extends ApprovalTestsBase {

  TestObjectConfig testObjectConfig = TestConfigManager.getTestSuiteConfig().getTestObject();

  private void updateTrustStoreWithAlternativeCerts(
      final Consumer<CertificateDto.CertificateDtoBuilder> certificateDtoDateConfigurer,
      final TslSignerApprovalTests.TslUpdateExpectation tslUpdateExpected,
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

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 4) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @Afo(afoId = "A_23225", description = "lokales Caching von Sperrinformationen und Toleranzzeiten")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in past within tolerance")
  void verifyOcspResponseTslSignerCertProducedAtPastWithinTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        -(testObjectConfig.getOcspToleranceProducedAtPastSeconds() * 1000
            - ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 3) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @Afo(afoId = "A_23225", description = "lokales Caching von Sperrinformationen und Toleranzzeiten")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in past out of tolerance")
  void verifyOcspResponseTslSignerCertProducedAtPastOutOfTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        -(testObjectConfig.getOcspToleranceProducedAtPastSeconds() * 1000
            + ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_025 (Data Variant 2) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @Afo(afoId = "A_23225", description = "lokales Caching von Sperrinformationen und Toleranzzeiten")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in future within tolerance")
  void verifyOcspResponseTslSignerCertProducedAtFutureWithinTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        testObjectConfig.getOcspToleranceProducedAtFutureSeconds() * 1000
            - ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @Afo(afoId = "A_23225", description = "lokales Caching von Sperrinformationen und Toleranzzeiten")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in future out of tolerance")
  void verifyOcspResponseTslSignerCertProducedAtFutureOutOfTolerance() {

    initialState();

    final int producedAtDeltaMilliseconds =
        testObjectConfig.getOcspToleranceProducedAtFutureSeconds() * 1000
            + ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with thisUpdate in future within tolerance")
  void verifyOcspResponseTslSignerCertThisUpdateFutureWithinTolerance() {

    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with thisUpdate in future out of tolerance")
  void verifyOcspResponseTslSignerCertThisUpdateFutureOutOfTolerance() {

    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds();

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
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
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with nextUpdate in past within tolerance")
  void verifyOcspResponseTslSignerCertNextUpdatePastWithinTolerance() {

    initialState();

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds),
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }

  /** gematikId: UE_PKI_TC_0105_029 (Data Variant 1) */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @Afo(
      afoId = "GS-A_5215",
      description = "Festlegung der zeitlichen Toleranzen in einer OCSP-Response")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with nextUpdate in past out of tolerance")
  void verifyOcspResponseTslSignerCertNextUpdatePastOutOfTolerance() {

    initialState();

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    updateTrustStoreWithAlternativeCerts(
        applyDateConfig(DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds),
        TSL_UPDATE_NOT_EXPECTED,
        USECASE_INVALID);

    establishDefaultTrustStoreAndExecuteUseCase();
  }
}
