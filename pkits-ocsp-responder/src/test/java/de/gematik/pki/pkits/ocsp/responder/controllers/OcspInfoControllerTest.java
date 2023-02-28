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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.ocsp.responder.data.OcspInfoRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import org.apache.http.HttpStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OcspInfoControllerTest {

  String ocspInfoUrl;
  String ocspServiceUrl;
  String ocspServiceUrlSeqNr42;
  @LocalServerPort private int localServerPort;

  private static final Path VALID_X509_ISSUER_CERT =
      Path.of("src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
  private static final Path VALID_X509_EE_CERT =
      Path.of("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
  private final P12Container signer;
  private final int delayMilliseconds = 0;

  OcspInfoControllerTest() {
    signer =
        P12Reader.getContentFromP12(
            PkitsCommonUtils.readContent("src/test/resources/certificates/eccOcspSigner.p12"),
            "00");
  }

  @BeforeAll
  void init() {

    ocspInfoUrl =
        "http://localhost:" + localServerPort + PkitsConstants.OCSP_WEBSERVER_INFO_ENDPOINT;
    ocspServiceUrl = "http://localhost:" + localServerPort + OCSP_SSP_ENDPOINT;
    ocspServiceUrlSeqNr42 = ocspServiceUrl + "/42";
  }

  /**
   * Get OcspRequestHistory. OcspResponder has just started, certSerialNr is imaginary - history
   * should be empty. Expected is a String that represents an empty array.
   */
  @Test
  void getEmptyOcspRequestHistoryForImaginaryCertAsJson() {
    final BigInteger certSerialNrImaginary = new BigInteger("42000");
    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            certSerialNrImaginary, OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(ocspInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(ocspInfoUrl, requestBodyAsJson);
    assertThat(responseBodyAsJson).isEqualTo("[]");
  }

  /**
   * Configure OcspResponder, Send Ocsp Request, Send InfoRequest, deserialize response, assert that
   * there is a history Delete full history via InfoRequest and check
   */
  @Test
  void deleteCompleteOcspRequestHistory() throws IOException {
    final CustomCertificateStatusDto certificateStatus = CustomCertificateStatusDto.createGood();
    final X509Certificate VALID_X509_EE_CERT =
        CertReader.readX509(OcspInfoControllerTest.VALID_X509_EE_CERT);
    final X509Certificate VALID_X509_ISSUER_CERT =
        CertReader.readX509(OcspInfoControllerTest.VALID_X509_ISSUER_CERT);
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
    // Configure OcspResponder
    OcspResponderTestUtils.configure(
        "http://localhost:" + localServerPort,
        VALID_X509_EE_CERT,
        certificateStatus,
        signer,
        delayMilliseconds);

    // Send Ocsp Request
    final HttpResponse<String> response =
        Unirest.post(ocspServiceUrlSeqNr42).body(ocspReq.getEncoded()).asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    // Expected is a history with at least one entry for serial number of VALID_X509_EE_CERT
    // here.

    {
      // Retrieve history for VALID_X509_EE_CERT and assert that there is a history (for this
      // certificate)
      final OcspInfoRequestDto ocspInfoRequestDto1 =
          new OcspInfoRequestDto(
              VALID_X509_EE_CERT.getSerialNumber(),
              OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
      final List<OcspRequestHistoryEntryDto> historyExcerpt1 =
          retrieveHistoryExcerpt(ocspInfoRequestDto1);
      assertThat(historyExcerpt1).isNotEmpty();
    }
    {
      // Retrieve history for imaginary certificate, delete full history and assert that there
      // is no history
      final OcspInfoRequestDto infoReqDeleteAll =
          new OcspInfoRequestDto(
              new BigInteger("10815"), OcspInfoRequestDto.HistoryDeleteOption.DELETE_FULL_HISTORY);
      final List<OcspRequestHistoryEntryDto> historyExcerpt2 =
          retrieveHistoryExcerpt(infoReqDeleteAll);
      assertThat(historyExcerpt2).isEmpty();
    }
    {
      // Retrieve history for VALID_X509_EE_CERT and assert that there is no history
      final OcspInfoRequestDto ocspInfoRequestDto3 =
          new OcspInfoRequestDto(
              VALID_X509_EE_CERT.getSerialNumber(),
              OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
      final List<OcspRequestHistoryEntryDto> historyExcerpt3 =
          retrieveHistoryExcerpt(ocspInfoRequestDto3);
      assertThat(historyExcerpt3).isEmpty();
    }
  }

  /**
   * Configure OcspResponder, Send Ocsp Request, Send InfoRequest, deserialize response, assert that
   * there is a history, Delete history for certificate via InfoRequest and check
   */
  @Test
  void deleteOcspRequestHistoryForCertificate() throws IOException {
    final CustomCertificateStatusDto certificateStatus = CustomCertificateStatusDto.createGood();
    final X509Certificate VALID_X509_EE_CERT =
        CertReader.readX509(OcspInfoControllerTest.VALID_X509_EE_CERT);
    final X509Certificate VALID_X509_ISSUER_CERT =
        CertReader.readX509(OcspInfoControllerTest.VALID_X509_ISSUER_CERT);
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);

    // Configure OcspResponder
    OcspResponderTestUtils.configure(
        "http://localhost:" + localServerPort,
        VALID_X509_EE_CERT,
        certificateStatus,
        signer,
        delayMilliseconds);

    // Send Ocsp Request
    final HttpResponse<String> response =
        Unirest.post(ocspServiceUrlSeqNr42).body(ocspReq.getEncoded()).asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    // Expected is a history with at least one entry for serial number of VALID_X509_EE_CERT
    // here.

    {
      // Retrieve history for VALID_X509_EE_CERT and assert that there is a history (for this
      // certificate)
      final OcspInfoRequestDto ocspInfoRequestDto1 =
          new OcspInfoRequestDto(
              VALID_X509_EE_CERT.getSerialNumber(),
              OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
      final List<OcspRequestHistoryEntryDto> historyExcerpt1 =
          retrieveHistoryExcerpt(ocspInfoRequestDto1);
      assertThat(historyExcerpt1).isNotEmpty();
    }
    {
      // Retrieve history for imaginary certificate, delete full history and assert that there
      // is no history
      final OcspInfoRequestDto infoReqDeleteAll =
          new OcspInfoRequestDto(
              new BigInteger("10815"), OcspInfoRequestDto.HistoryDeleteOption.DELETE_CERT_HISTORY);
      final List<OcspRequestHistoryEntryDto> historyExcerpt2 =
          retrieveHistoryExcerpt(infoReqDeleteAll);
      assertThat(historyExcerpt2).isEmpty();
    }
    {
      // Retrieve history for VALID_X509_EE_CERT and assert that there is no history
      final OcspInfoRequestDto ocspInfoRequestDto3 =
          new OcspInfoRequestDto(
              VALID_X509_EE_CERT.getSerialNumber(),
              OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
      final List<OcspRequestHistoryEntryDto> historyExcerpt3 =
          retrieveHistoryExcerpt(ocspInfoRequestDto3);
      assertThat(historyExcerpt3).isNotEmpty();
    }
    {
      // Retrieve history for VALID_X509_EE_CERT, delete certificate history and assert that
      // there is history
      final OcspInfoRequestDto ocspInfoRequestDto4 =
          new OcspInfoRequestDto(
              VALID_X509_EE_CERT.getSerialNumber(),
              OcspInfoRequestDto.HistoryDeleteOption.DELETE_CERT_HISTORY);
      final List<OcspRequestHistoryEntryDto> historyExcerpt4 =
          retrieveHistoryExcerpt(ocspInfoRequestDto4);
      assertThat(historyExcerpt4).isNotEmpty();
    }
    {
      // Retrieve history for VALID_X509_EE_CERT and assert that there is no history
      final OcspInfoRequestDto ocspInfoRequestDto5 =
          new OcspInfoRequestDto(
              VALID_X509_EE_CERT.getSerialNumber(),
              OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
      final List<OcspRequestHistoryEntryDto> historyExcerpt5 =
          retrieveHistoryExcerpt(ocspInfoRequestDto5);
      assertThat(historyExcerpt5).isEmpty();
    }
  }

  /**
   * Retrieve an excerpt of the Ocsp request history for a certificate. Send InfoRequest and
   * deserialize response.
   *
   * @param ocspInfoRequestDto Request to sent
   * @return historyExcerpt as list
   */
  private List<OcspRequestHistoryEntryDto> retrieveHistoryExcerpt(
      final OcspInfoRequestDto ocspInfoRequestDto) {

    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(ocspInfoRequestDto);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(ocspInfoUrl, requestBodyAsJson);

    return PkitsCommonUtils.convertToList(responseBodyAsJson, OcspRequestHistoryEntryDto.class);
  }
}
