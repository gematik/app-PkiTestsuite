/*
 * Copyright (c) 2022 gematik GmbH
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

import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_DEFAULT_USECASE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.EXPECT_FAILURE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.EXPECT_PASS;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusType;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.OcspResponderConfigDtoBuilder;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.config.Afo;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.io.IOException;
import java.nio.file.Path;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
class TslSignerApprovalTestsIT extends ApprovalTestsBaseIT {

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

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    final P12Container ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(ocspSignerFilename),
            ocspSettings.getSignerPassword());

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder().eeCert(readTslSignerCert()).signer(ocspSigner);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

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

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    final OcspResponderConfigDtoBuilder ocspConfigWrongSignature =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .validSignature(false);

    tslDownload.configureOcspResponderTslSignerStatusGood(ocspConfigWrongSignature);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

  private void verifyOcspResponseDateForTslSignerCert(
      final DtoDateConfigOption dateConfigOption,
      final int deltaMilliseconds,
      final UseCaseResult useCaseResult)
      throws DatatypeConfigurationException, IOException {

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder().eeCert(readTslSignerCert()).signer(ocspSigner);

    switch (dateConfigOption) {
      case THIS_UPDATE -> dtoBuilder.thisUpdateDeltaMilliseconds(deltaMilliseconds);
      case PRODUCED_AT -> dtoBuilder.producedAtDeltaMilliseconds(deltaMilliseconds);
      case NEXT_UPDATE -> dtoBuilder.nextUpdateDeltaMilliseconds(deltaMilliseconds);
    }

    log.info("tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);");
    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);

    log.info(
        "tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject()), {}",
        tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());

    log.info("tslDownload.waitUntilOcspRequestForSigner()");
    tslDownload.waitUntilOcspRequestForSigner();

    final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour;

    if (useCaseResult == EXPECT_PASS) {
      ocspRequestExpectationBehaviour = OCSP_REQUEST_EXPECT;
    } else {
      ocspRequestExpectationBehaviour = OCSP_REQUEST_DO_NOT_EXPECT;
    }

    final Path certPath = getPathOfAlternativeCertificate();
    log.info(
        "useCaseWithCert(certPath, useCaseResult, OCSP_RESP_TYPE_DEFAULT_USECASE,"
            + " ocspRequestExpectationBehaviour);");
    useCaseWithCert(
        certPath, useCaseResult, OCSP_RESP_TYPE_DEFAULT_USECASE, ocspRequestExpectationBehaviour);
  }

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
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_PASS);
  }

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
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_FAILURE);
  }

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
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_PASS);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

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
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_FAILURE);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + producedAtDeltaMilliseconds / 1000);
  }

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
        DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds, EXPECT_PASS);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

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
        DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds, EXPECT_FAILURE);

    waitForOcspCacheToExpire(
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + thisUpdateDeltaMilliseconds / 1000);
  }

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
        DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds, EXPECT_PASS);
  }

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
        DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds, EXPECT_FAILURE);
  }

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
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .nextUpdateDeltaMilliseconds(null);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

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
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .respStatus(ocspRespStatus)
            .withResponseBytes(withResponseBytes);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

  @Test
  // TODO @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7b")
  @DisplayName("Test OCSP response of TSL signer certificate with missing CertHash")
  void verifyOcspResponseTslSignerCertMissingCertHash(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .withCertHash(false);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();

    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

  @Test
  // TODO @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7c")
  @DisplayName("Test OCSP response of TSL signer certificate with invalid CertHash")
  void verifyOcspResponseTslSignerCertInvalidCertHash(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .validCertHash(false);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();

    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

  @ParameterizedTest
  @EnumSource(
      value = CustomCertificateStatusType.class,
      names = {"UNKNOWN", "REVOKED"})
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 4")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 8b and 8c")
  @DisplayName("Test OCSP response of TSL signer certificate with status revoked and unknown")
  void verifyOcspResponseTslSignerCertStatusRevokedAndUnknown(
      final CustomCertificateStatusType customCertificateStatusType, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .certificateStatus(CustomCertificateStatusDto.create(customCertificateStatusType));

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);

    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }

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
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .responderIdType(ResponderIdType.BY_NAME);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();

    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  @ParameterizedTest
  // TODO @Afo(afoId = "RFC 5280", description = "4.1.1.2. signatureAlgorithm")
  @ValueSource(booleans = {true, false})
  @DisplayName("Test OCSP response of TSL signer certificate with null parameter in CertId")
  void verifyOcspResponseTslSignerCertWithNullParameterInCertId(
      final boolean withNullParameterHashAlgoOfCertId, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilder);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    final Path certPath = getPathOfAlternativeCertificate();

    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  @Test
  // TODO @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP check - step 4c")
  @DisplayName("Test OCSP response TSL signer certificate with timeout and delay")
  void verifyOcspResponseTslSignerCertTimeoutAndDelay(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int shortDelayMilliseconds =
        timeoutAndDelayFuncMap.get("shortDelay").apply(testSuiteConfig);

    final int longDelayMilliseconds =
        timeoutAndDelayFuncMap.get("longDelay").apply(testSuiteConfig);

    final OcspResponderConfigDtoBuilder dtoBuilderShort =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .delayMilliseconds(shortDelayMilliseconds);

    final OcspResponderConfigDtoBuilder dtoBuilderLong =
        OcspResponderConfigDto.builder()
            .eeCert(readTslSignerCert())
            .signer(ocspSigner)
            .delayMilliseconds(longDelayMilliseconds);

    final Path certPath = getPathOfAlternativeCertificate();

    int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood(dtoBuilderShort);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());
    tslDownload.waitUntilOcspRequestForSigner();

    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);

    testCaseMessage(testInfo);
    initialState();

    offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownloadLong = getTslDownloadAlternativeTemplate(offeredSeqNr);

    tslDownloadLong.configureOcspResponderTslSignerStatusGood(dtoBuilderLong);
    tslDownloadLong.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());

    tslDownloadLong.waitUntilOcspRequestForSigner();

    useCaseWithCert(
        certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
  }
}
