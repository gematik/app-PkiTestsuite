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

import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTestsIT.TslUpdateExpectation.TSL_UPDATE_EXPECTED;
import static de.gematik.pki.pkits.testsuite.approval.TslSignerApprovalTestsIT.TslUpdateExpectation.TSL_UPDATE_NOT_EXPECTED;
import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_DEFAULT_USECASE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_VALID;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_KEY_USAGE_CHECK_DISABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_VALIDITY_CHECK_DISABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static java.lang.Integer.max;
import static java.lang.Math.round;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslUtils;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusType;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.OcspResponderConfigDtoBuilder;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.config.Afo;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI TSL signer approval tests.")
@Order(1)
class TslSignerApprovalTestsIT extends ApprovalTestsBaseIT {

  enum TslUpdateExpectation {
    TSL_UPDATE_EXPECTED,
    TSL_UPDATE_NOT_EXPECTED
  }

  private void updateTrustStoreUsingOcspResponderConfig(
      final Path tslTemplate,
      final OcspResponderConfigDtoBuilder ocspResponderConfigDtoBuilder,
      final TslUpdateExpectation tslUpdateExpected,
      final Path certPath,
      final UseCaseResult useCaseResult)
      throws DatatypeConfigurationException, IOException {

    currentTestInfo.setPhase("updateTrustStoreUsingOcspResponderConfig");

    log.info(
        "START updateTrustStoreUsingOcspResponderConfig - {}",
        PkitsTestSuiteUtils.getCallerTrace());
    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadWithTemplate(offeredSeqNr, tslTemplate);

    printCurrentTslSeqNr();
    tslDownload.configureOcspResponderTslSignerStatusGood(ocspResponderConfigDtoBuilder);
    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner(getExpectedOcspTslSeqNr());

    if (tslUpdateExpected == TSL_UPDATE_EXPECTED) {
      tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);
    }
    final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour;

    if (useCaseResult == USECASE_VALID) {
      ocspRequestExpectationBehaviour = OCSP_REQUEST_EXPECT;
    } else {
      ocspRequestExpectationBehaviour = OCSP_REQUEST_DO_NOT_EXPECT;
    }

    useCaseWithCert(
        certPath, useCaseResult, OCSP_RESP_TYPE_DEFAULT_USECASE, ocspRequestExpectationBehaviour);
    log.info(
        "END updateTrustStoreUsingOcspResponderConfig - {}", PkitsTestSuiteUtils.getCallerTrace());
    currentTestInfo.resetPhase();
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
  void verifyMissingOcspSignerInTslForTslSignerCert(
      final String ocspSignerFilename, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final P12Container ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(ocspSignerFilename),
            ocspSettings.getSignerPassword());

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder().eeCert(getDefaultTslSignerCert()).signer(ocspSigner);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_019 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a1")
  @DisplayName("Test invalid OCSP response signature for TSL signer certificate")
  void verifyOcspResponseWithInvalidSignatureForTslSignerCert(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .validSignature(false);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  private void verifyOcspResponseDateForTslSignerCert(
      final DtoDateConfigOption dateConfigOption,
      final int deltaMilliseconds,
      final TslUpdateExpectation tslUpdateExcected,
      final UseCaseResult useCaseResult)
      throws DatatypeConfigurationException, IOException {

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder().eeCert(getDefaultTslSignerCert()).signer(ocspSigner);

    switch (dateConfigOption) {
      case THIS_UPDATE -> dtoBuilder.thisUpdateDeltaMilliseconds(deltaMilliseconds);
      case PRODUCED_AT -> dtoBuilder.producedAtDeltaMilliseconds(deltaMilliseconds);
      case NEXT_UPDATE -> dtoBuilder.nextUpdateDeltaMilliseconds(deltaMilliseconds);
    }

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        tslUpdateExcected,
        getPathOfAlternativeCertificate(),
        useCaseResult);
  }

  /** gematikId: UE_PKI_TC_0105_025 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in past within tolerance")
  void verifyOcspResponseTslSignerCertProducedAtPastWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.PRODUCED_AT,
        producedAtDeltaMilliseconds,
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_025 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in past out of tolerance")
  void verifyOcspResponseTslSignerCertProducedAtPastOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.PRODUCED_AT,
        producedAtDeltaMilliseconds,
        TSL_UPDATE_NOT_EXPECTED,
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_025 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in future within tolerance")
  void verifyOcspResponseTslSignerCertProducedAtFutureWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.PRODUCED_AT,
        producedAtDeltaMilliseconds,
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TC_0105_025 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with producedAt in future out of tolerance")
  void verifyOcspResponseTslSignerCertProducedAtFutureOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds()
            + 1000 * testSuiteConfig.getTestObject().getOcspGracePeriodSeconds();

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.PRODUCED_AT,
        producedAtDeltaMilliseconds,
        TSL_UPDATE_NOT_EXPECTED,
        USECASE_INVALID);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TC_0105_026 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with thisUpdate in future within tolerance")
  void verifyOcspResponseTslSignerCertThisUpdateFutureWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.THIS_UPDATE,
        thisUpdateDeltaMilliseconds,
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TC_0105_026 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with thisUpdate in future out of tolerance")
  void verifyOcspResponseTslSignerCertThisUpdateFutureOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.THIS_UPDATE,
        thisUpdateDeltaMilliseconds,
        TSL_UPDATE_NOT_EXPECTED,
        USECASE_INVALID);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

  /** gematikId: UE_PKI_TC_0105_029 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with nextUpdate in past within tolerance")
  void verifyOcspResponseTslSignerCertNextUpdatePastWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.NEXT_UPDATE,
        nextUpdateAtDeltaMilliseconds,
        TSL_UPDATE_EXPECTED,
        USECASE_VALID);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_029 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName(
      "Test OCSP response of TSL signer certificate with nextUpdate in past out of tolerance")
  void verifyOcspResponseTslSignerCertNextUpdatePastOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDateForTslSignerCert(
        DtoDateConfigOption.NEXT_UPDATE,
        nextUpdateDeltaMilliseconds,
        TSL_UPDATE_NOT_EXPECTED,
        USECASE_INVALID);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_034 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response of TSL signer certificate with missing nextUpdate")
  void verifyOcspResponseTslSignerCertMissingNextUpdate(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .nextUpdateDeltaMilliseconds(null);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
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
      final OCSPRespStatus ocspRespStatus, final boolean withResponseBytes, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .respStatus(ocspRespStatus)
            .withResponseBytes(withResponseBytes);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_036 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7b")
  @DisplayName("Test OCSP response of TSL signer certificate with missing CertHash")
  void verifyOcspResponseTslSignerCertMissingCertHash(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .withCertHash(false);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_036 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7c")
  @DisplayName("Test OCSP response of TSL signer certificate with invalid CertHash")
  void verifyOcspResponseTslSignerCertInvalidCertHash(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .validCertHash(false);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
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
      final CustomCertificateStatusType customCertificateStatusType, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .certificateStatus(CustomCertificateStatusDto.create(customCertificateStatusType));

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_022 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName("Test OCSP response of TSL signer certificate with responder id byName")
  void verifyOcspResponseTslSignerCertResponderIdByName(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .responderIdType(ResponderIdType.BY_NAME);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
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
      final boolean withNullParameterHashAlgoOfCertId, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0105_021 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP check - step 4c")
  @DisplayName("Test OCSP response TSL signer certificate with timeout and delay")
  void verifyOcspResponseTslSignerCertTimeoutAndDelay(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int longDelayMilliseconds =
        timeoutAndDelayFuncMap.get("longDelay").apply(testSuiteConfig);

    final OcspResponderConfigDtoBuilder dtoBuilderLong =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .delayMilliseconds(longDelayMilliseconds);

    final int shortDelayMilliseconds =
        timeoutAndDelayFuncMap.get("shortDelay").apply(testSuiteConfig);

    final OcspResponderConfigDtoBuilder dtoBuilderShort =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .delayMilliseconds(shortDelayMilliseconds);

    final int tslProcessingTimeSeconds =
        testSuiteConfig.getTestObject().getTslProcessingTimeSeconds();

    final int tslProcessingTimeSecondsNew =
        max(
            tslProcessingTimeSeconds,
            round((float) longDelayMilliseconds / 1000) + ocspSettings.getGracePeriodExtraDelay());

    testSuiteConfig.getTestObject().setTslProcessingTimeSeconds(tslProcessingTimeSecondsNew);

    try {
      updateTrustStoreUsingOcspResponderConfig(
          tslSettings.getAlternativeTemplate(),
          dtoBuilderLong,
          TSL_UPDATE_NOT_EXPECTED,
          getPathOfAlternativeCertificate(),
          USECASE_INVALID);

      updateTrustStoreUsingOcspResponderConfig(
          tslSettings.getAlternativeTemplate(),
          dtoBuilderShort,
          TSL_UPDATE_EXPECTED,
          getPathOfAlternativeCertificate(),
          USECASE_VALID);
    } catch (final Exception e) {
      testSuiteConfig.getTestObject().setTslProcessingTimeSeconds(tslProcessingTimeSeconds);
      throw e;
    }

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
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
      final CertificateIdGeneration certificateIdGeneration, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(getDefaultTslSignerCert())
            .signer(ocspSigner)
            .certificateIdGeneration(certificateIdGeneration);

    updateTrustStoreUsingOcspResponderConfig(
        tslSettings.getAlternativeTemplate(),
        dtoBuilder,
        TSL_UPDATE_NOT_EXPECTED,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
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
  void verifyTslSignerCertNotYetValid(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    verifyForBadCertificateFromTrustAnchors(
        "ee_not-yet-valid.p12", SIGNER_KEY_USAGE_CHECK_ENABLED, SIGNER_VALIDITY_CHECK_DISABLED);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
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
  void verifyTslSignerCertExpired(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    verifyForBadCertificateFromTrustAnchors(
        "ee_expired.p12", SIGNER_KEY_USAGE_CHECK_ENABLED, SIGNER_VALIDITY_CHECK_DISABLED);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  private void breakTslSigner(final TslDownload tslDownload)
      throws CertificateEncodingException, IOException {

    final byte[] tslBytes = tslDownload.getTslBytes();
    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);
    final X509Certificate signerCert = TslUtils.getFirstTslSignerCertificate(tsl);

    final byte[] signerCertBrokenBytes = signerCert.getEncoded();
    GemLibPkiUtils.change4Bytes(signerCertBrokenBytes, 4);

    final byte[] tslWithSignerCertBroken =
        TslModifier.modifiedSignerCert(tslBytes, signerCertBrokenBytes);

    tslDownload.setTslBytes(tslWithSignerCertBroken);
    writeTsl(tslDownload, "_modified");
  }

  /** gematikId: UE_PKI_TC_0105_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 3")
  @DisplayName("Test TSL signer certificate is broken")
  void verifyTslSignerCertBroken(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException, CertificateEncodingException {

    testCaseMessage(testInfo);
    initialState();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood();

    breakTslSigner(tslDownload);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());

    assertNoOcspRequest(tslDownload);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);

    final Path validCertPath = getPathOfFirstValidCert();
    useCaseWithCert(
        validCertPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  private void verifyForBadCertificateFromTrustAnchors(
      final String p12Filename,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck)
      throws DatatypeConfigurationException, IOException {

    final Path p12ContainerBadPath = Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, p12Filename);
    final P12Container p12ContainerBad = P12Reader.getContentFromP12(p12ContainerBadPath, "00");

    final Path tslTemplate = tslSettings.getAlternativeTemplate();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload =
        getTslDownloadWithTemplateAndSigner(
            offeredSeqNr,
            tslTemplate,
            p12ContainerBadPath,
            signerKeyUsageCheck,
            signerValidityCheck);

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(p12ContainerBad.getCertificate())
            .signer(ocspSigner);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSignerOptional();

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
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
  void verifyTslSignerCertInvalidKeyUsageAndExtendedKeyUsage(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    verifyForBadCertificateFromTrustAnchors(
        "ee_invalid-ext-keyusage.p12",
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);

    verifyForBadCertificateFromTrustAnchors(
        "ee_invalid-keyusage.p12", SIGNER_KEY_USAGE_CHECK_DISABLED, SIGNER_VALIDITY_CHECK_ENABLED);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }
}
