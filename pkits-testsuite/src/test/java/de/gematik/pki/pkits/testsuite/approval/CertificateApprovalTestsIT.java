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
import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_DEFAULT_USECASE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.EXPECT_FAILURE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.EXPECT_PASS;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.PKITS_CERT.PKITS_CERT_INVALID;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.PKITS_CERT.PKITS_CERT_VALID;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.testsuite.common.CertificateProvider;
import de.gematik.pki.pkits.testsuite.common.VariableSource;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import java.io.IOException;
import java.nio.file.Path;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

@Slf4j
@DisplayName("PKI certificate approval tests.")
@TestMethodOrder(OrderAnnotation.class)
class CertificateApprovalTestsIT extends ApprovalTestsBaseIT {

  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4652",
      description = "TUC_PKI_018: Zertifikatspr??fung in der TI - positive case")
  @Afo(
      afoId = "GS-A_4663",
      description = "Zertifikats-Pr??fparameter f??r den TLS-Handshake - positive case")
  @Afo(afoId = "GS-A_4357", description = "ECDSA algorithms - Tab_KRYPT_002a")
  @Afo(afoId = "A_17124", description = "ECDSA cipher suites for TLS")
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_VALID)
  @DisplayName("Test use case with valid certificates")
  void verifyConnectCertsValid(final Path certPath, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {
    testCaseMessage(testInfo);
    initialState();
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
  }

  @Test
  @Afo(afoId = "GS-A_4357", description = "RSA algorithms - Tab_KRYPT_002")
  @Afo(afoId = "GS-A_4384", description = "RSA cipher suites for TLS")
  @Disabled("Our SUT does not support RSA yet")
  @DisplayName("Test use case with valid RSA certificate")
  void verifyConnectCertsValidRsa(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);

    initialState();

    final Path certPath = Path.of("../testDataTemplates/certificates/valid-rsa/ee_default-rsa.p12");

    final P12Container signer =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve("ocspSignerRsa.p12"),
            ocspSettings.getSignerPassword());

    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(signer)
            .build());

    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM, OCSP_REQUEST_EXPECT);
  }

  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4652",
      description = "TUC_PKI_018: Zertifikatspr??fung in der TI - negative cases")
  @Afo(
      afoId = "GS-A_4663",
      description = "Zertifikats-Pr??fparameter f??r den TLS-Handshake - negative cases")
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_INVALID)
  @DisplayName("Test use case with invalid certificates")
  void verifyConnectCertsInvalid(final Path certPath, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    log.info("\nCertificate path: {}\n", certPath);

    initialState();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_IGNORE);

    // TODO: ee_invalid-extension-crit.p12 does not throw...?

  }
}
