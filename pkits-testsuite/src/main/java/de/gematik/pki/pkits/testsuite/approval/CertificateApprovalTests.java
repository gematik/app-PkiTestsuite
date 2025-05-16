/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.KEYSTORE_PASSWORD;
import static de.gematik.pki.pkits.testsuite.common.PkitsCertType.PKITS_CERT_VALID_RSA;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_PRECONFIGURED;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.common.CertificateProvider;
import de.gematik.pki.pkits.testsuite.common.PkitsCertType;
import de.gematik.pki.pkits.testsuite.common.VariableSource;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

@Slf4j
@DisplayName("PKI certificate approval tests.")
@Order(1)
class CertificateApprovalTests extends ApprovalTestsBase {

  /** gematikId: UE_PKI_TS_0302_009, UE_PKI_TS_0302_041, UE_PKI_TS_0302_036 */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4652",
      description = "TUC_PKI_018: Zertifikatsprüfung in der TI - positive cases")
  @Afo(
      afoId = "GS-A_4663",
      description = "Zertifikats-Prüfparameter für den TLS-Handshake - positive cases")
  @Afo(afoId = "GS-A_4357", description = "ECDSA algorithms - Tab_KRYPT_002a")
  @Afo(afoId = "GS-A_4385", description = "TLS-Verbindungen, Version 1.2")
  @Afo(afoId = "A_17124", description = "ECDSA cipher suites for TLS")
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PkitsCertType.PKITS_CERT_VALID)
  @DisplayName("Test use case with valid certificates")
  void verifyUseCaseCertsValid(final Path eeCertPath, final Path issuerCertPath) {

    initialState();

    useCaseWithCert(
        eeCertPath,
        issuerCertPath,
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0305_001 */
  @ParameterizedTest
  @Afo(afoId = "GS-A_4357", description = "RSA algorithms - Tab_KRYPT_002")
  @Afo(afoId = "GS-A_4384", description = "RSA cipher suites for TLS")
  @DisplayName("Test use case with valid RSA certificate")
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_VALID_RSA)
  void verifyUseCaseRsaCertValid(final Path eeCertPath, final Path issuerCertPath) {

    initialState(PKITS_CERT_VALID_RSA);

    final X509Certificate issuerCert = CertReader.readX509(issuerCertPath);

    final OcspResponderConfig config =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(CertReader.getX509FromP12(eeCertPath, KEYSTORE_PASSWORD))
                        .issuerCert(issuerCert)
                        .signer(PkitsTestDataConstants.OCSP_SIGNER_RSA)
                        .build()))
            .build();

    TestEnvironment.configureOcspResponder(ocspResponderUri, config);

    useCaseWithCert(
        eeCertPath, issuerCertPath, USECASE_VALID, OCSP_RESP_PRECONFIGURED, OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TS_0302_001 */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4652",
      description = "TUC_PKI_018: Zertifikatsprüfung in der TI - negative cases")
  @Afo(
      afoId = "GS-A_4663",
      description = "Zertifikats-Prüfparameter für den TLS-Handshake - negative cases")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 2")
  @Afo(
      afoId = "GS-A_4656",
      description = "TUC_PKI_005: Adresse für Status- und Sperrprüfung ermitteln - Schritt 2b")
  @Afo(afoId = "GS-A_4654", description = "TUC_PKI_003: CA-Zertifikat finden - Schritt 3")
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PkitsCertType.PKITS_CERT_VALID_ALTERNATIVE)
  @DisplayName("Test use case with valid certificates with issuer not in trust store")
  void verifyUseCaseCertsNotInTsl(final Path eeCertPathAlternative, final Path issuerCertPath) {

    initialState();

    useCaseWithCert(
        eeCertPathAlternative,
        issuerCertPath,
        USECASE_INVALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_DO_NOT_EXPECT);
  }

  /**
   * gematikId: UE_PKI_TS_0302_003, UE_PKI_TS_0302_005, UE_PKI_TS_0302_006, UE_PKI_TS_0302_040,
   * UE_PKI_TS_0302_010
   */
  @ParameterizedTest
  @Afo(
      afoId = "GS-A_4652",
      description = "TUC_PKI_018: Zertifikatsprüfung in der TI - negative cases")
  @Afo(
      afoId = "GS-A_4663",
      description = "Zertifikats-Prüfparameter für den TLS-Handshake - negative cases")
  @Afo(afoId = "GS-A_4657", description = "TUC_PKI_006: OCSP-Abfrage - Schritt 2")
  @Afo(
      afoId = "GS-A_4656",
      description = "TUC_PKI_005: Adresse für Status- und Sperrprüfung ermitteln - Schritt 2b")
  @Afo(afoId = "GS-A_4654", description = "TUC_PKI_003: CA-Zertifikat finden - Schritt 3")
  @Afo(
      afoId = "GS-A_4655",
      description = "TUC_PKI_004: Mathematische Prüfung der Zertifikatssignatur")
  @Afo(afoId = "GS-A_4661", description = "kritische Erweiterungen in Zertifikaten")
  @Afo(afoId = "RFC 5280", description = "4.2.1. Certificate Extensions")
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PkitsCertType.PKITS_CERT_INVALID)
  @DisplayName("Test use case with invalid certificates")
  void verifyUseCaseCertsInvalid(final Path eeCertPath, final Path issuerCertPath) {

    initialState();

    // NOTE: we ignore OCSP requests, although in some cases the specification defines that OCSP
    // requests are expected or not expected
    useCaseWithCert(
        eeCertPath,
        issuerCertPath,
        USECASE_INVALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_IGNORE);
  }
}
