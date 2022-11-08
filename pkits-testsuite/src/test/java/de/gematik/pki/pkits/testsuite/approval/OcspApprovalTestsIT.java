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

import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_CUSTOM;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.EXPECT_FAILURE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.EXPECT_PASS;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusType;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.io.IOException;
import java.nio.file.Path;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI OCSP approval tests.")
@TestMethodOrder(OrderAnnotation.class)
class OcspApprovalTestsIT extends ApprovalTestsBaseIT {

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 1")
  @DisplayName("Test OCSP grace period")
  void verifyOcspGracePeriod(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dtoGood =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .build();

    final OcspResponderConfigDto dtoUnknown =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoUnknown);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoGood);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 4c")
  @DisplayName("Test OCSP response with timeout and delay")
  void verifyOcspResponseTimeoutAndDelay(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final int shortDelayMilliseconds =
        timeoutAndDelayFuncMap.get("shortDelay").apply(testSuiteConfig);

    final OcspResponderConfigDto dtoShort =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .delayMilliseconds(shortDelayMilliseconds)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoShort);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);

    final int longDelayMilliseconds =
        timeoutAndDelayFuncMap.get("longDelay").apply(testSuiteConfig);

    final OcspResponderConfigDto dtoLongDelay =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .delayMilliseconds(longDelayMilliseconds)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoLongDelay);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_DO_NOT_EXPECT);
  }

  @ParameterizedTest
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a")
  @DisplayName("Test missing OCSP signer in TSL")
  @ValueSource(
      strings = {
        TestSuiteConstants.OCSP_SIGNER_NOT_IN_TSL_FILENAME,
        TestSuiteConstants.OCSP_SIGNER_DIFFERENT_KEY
      })
  void verifyMissingOcspSignerInTsl(final String signerFilename, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    final P12Container signer =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(signerFilename),
            ocspSettings.getSignerPassword());

    final Path certPath = getPathOfFirstValidCert();

    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(signer)
            .build());

    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 5a1")
  @DisplayName("Test invalid signature in OCSP response")
  void verifyInvalidSignatureInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();
    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .validSignature(false)
            .build());

    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  private void verifyOcspResponseDate(
      final DtoDateConfigOption dateConfigOption,
      final int deltaMilliseconds,
      final UseCaseResult useCaseResult) {

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto.OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner);

    switch (dateConfigOption) {
      case THIS_UPDATE -> dtoBuilder.thisUpdateDeltaMilliseconds(deltaMilliseconds);
      case PRODUCED_AT -> dtoBuilder.producedAtDeltaMilliseconds(deltaMilliseconds);
      case NEXT_UPDATE -> dtoBuilder.nextUpdateDeltaMilliseconds(deltaMilliseconds);
    }

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoBuilder.build());
    useCaseWithCert(certPath, useCaseResult, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in past within tolerance")
  void verifyOcspResponseProducedAtPastWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_PASS);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in past out of tolerance")
  void verifyOcspResponseProducedAtPastOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_FAILURE);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in future within tolerance")
  void verifyOcspResponseProducedAtFutureWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_PASS);

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

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with producedAt in future out of tolerance")
  void verifyOcspResponseProducedAtFutureOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_FAILURE);
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

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with thisUpdate in future within tolerance")
  void verifyOcspResponseThisUpdateFutureWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds, EXPECT_PASS);

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

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with thisUpdate in future out of tolerance")
  void verifyOcspResponseThisUpdateFutureOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds, EXPECT_FAILURE);

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

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with nextUpdate in past within tolerance")
  void verifyOcspResponseNextUpdatePastWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds, EXPECT_PASS);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6")
  @DisplayName("Test OCSP response with nextUpdate in past out of tolerance")
  void verifyOcspResponseNextUpdatePastOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds, EXPECT_FAILURE);
  }

  @Test
  // TODO @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6a")
  @DisplayName("Test OCSP response with missing nextUpdate")
  void verifyOcspResponseMissingNextUpdate(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .nextUpdateDeltaMilliseconds(null)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @ParameterizedTest
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6a")
  @MethodSource(
      "de.gematik.pki.pkits.testsuite.common.TestSuiteConstants#provideOcspResponseVariousStatusAndResponseBytes")
  @DisplayName("Test various status of OCSP responses with and without response bytes")
  void verifyOcspResponseVariousStatusAndResponseBytes(
      final OCSPRespStatus ocspRespStatus, final boolean withResponseBytes, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .respStatus(ocspRespStatus)
            .withResponseBytes(withResponseBytes)
            .build();
    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 6b")
  @Afo(afoId = "", description = "")
  @DisplayName("Test invalid cert id in OCSP response")
  void verifyInvalidCerIdInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();
    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .validCertId(false)
            .build());

    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7b")
  @DisplayName("Test missing CertHash in OCSP response")
  void verifyMissingCertHashInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();
    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .withCertHash(false)
            .build());

    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 7c")
  @DisplayName("Test invalid CertHash in OCSP response")
  void verifyInvalidCertHashInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    final Path certPath = getPathOfFirstValidCert();

    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .validCertHash(false)
            .build());

    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @ParameterizedTest
  @EnumSource(
      value = CustomCertificateStatusType.class,
      names = {"UNKNOWN", "REVOKED"})
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 8b and 8c")
  @DisplayName("Test OCSP response with certificate status revoked and unknown")
  void verifyOcspCertificateStatusRevokedAndUnknown(
      final CustomCertificateStatusType customCertificateStatusType, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .certificateStatus(CustomCertificateStatusDto.create(customCertificateStatusType))
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @DisplayName("Test OCSP response with responder id byName")
  void verifyOcspResponseResponderIdByName(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .responderIdType(ResponderIdType.BY_NAME)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @ParameterizedTest
  @Afo(afoId = "RFC 6960", description = "4.2.1. ASN.1 Specification of the OCSP Response")
  @Afo(afoId = "RFC 5280", description = "4.1.1.2. signatureAlgorithm")
  @ValueSource(booleans = {true, false})
  @DisplayName("Test OCSP response with null parameter in CertId")
  void verifyOcspResponseWithNullParameterInCertId(
      final boolean withNullParameterHashAlgoOfCertId, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }
}
