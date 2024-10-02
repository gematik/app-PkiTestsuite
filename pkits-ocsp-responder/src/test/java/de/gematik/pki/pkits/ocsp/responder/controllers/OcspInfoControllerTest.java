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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_REQUEST;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatList;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspInfoRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspInfoRequestDto.HistoryDeleteOption;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OcspInfoControllerTest {

  private final int imaginaryNumber = 10000815;
  private final int tslSeqNrFromOcspRequest = 420000;

  private final X509Certificate VALID_X509_EE_CERT =
      OcspResponderTestUtils.getValidEeCert("DrMedGunther.pem");

  private final X509Certificate VALID_X509_ISSUER_CERT =
      CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

  private String ocspInfoUrl;
  private String ocspServiceUrlSeqNr42;
  @LocalServerPort private int localServerPort;

  private final P12Container signer = OcspResponderTestUtils.getSigner();

  @BeforeAll
  void init() {

    ocspInfoUrl =
        "http://localhost:" + localServerPort + PkitsConstants.OCSP_WEBSERVER_INFO_ENDPOINT;
    final String ocspServiceUrl = "http://localhost:" + localServerPort + OCSP_SSP_ENDPOINT;
    ocspServiceUrlSeqNr42 = ocspServiceUrl + "/" + tslSeqNrFromOcspRequest;
  }

  @BeforeEach
  void initEach(final TestInfo testInfo) {

    log.info("{}: start", testInfo.getTestMethod().orElseThrow().getName());
  }

  @AfterEach
  void teraDownEach(final TestInfo testInfo) {
    log.info("{}: end", testInfo.getTestMethod().orElseThrow().getName());
  }

  /**
   * Get OcspRequestHistory. OcspResponder has just started, certSerialNr is imaginary - history
   * should be empty. Expected is a String that represents an empty array.
   */
  @Test
  void getEmptyOcspRequestHistoryForImaginaryCertAsJson() {
    final BigInteger certSerialNrImaginary = new BigInteger("420000");

    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            OcspResponderManager.IGNORE_SEQUENCE_NUMBER,
            certSerialNrImaginary,
            HistoryDeleteOption.DELETE_NOTHING);

    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(ocspInfoRequest);

    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(ocspInfoUrl, requestBodyAsJson);

    assertThat(responseBodyAsJson).isEqualTo("[]");
  }

  @Test
  void getEmptyOcspRequestHistoryForImaginaryCertAsJson2() {
    final String requestBodyAsJson =
        """
            {
                "tslSeqNr": -1,
                "certSerialNr": 420000,
                "historyDeleteOption": "DELETE_NOTHING"
            }
            """;
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(ocspInfoUrl, requestBodyAsJson);

    assertThat(responseBodyAsJson).isEqualTo("[]");
  }

  private void initializeForHistory() throws IOException {

    final CustomCertificateStatusDto certificateStatus = CustomCertificateStatusDto.createGood();

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);

    retrieveHistoryExcerpt(
        OcspResponderManager.IGNORE_SEQUENCE_NUMBER,
        OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER,
        HistoryDeleteOption.DELETE_FULL_HISTORY);

    final List<OcspRequestHistoryEntryDto> historyExcerpt =
        retrieveHistoryExcerpt(
            OcspResponderManager.IGNORE_SEQUENCE_NUMBER,
            OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER,
            HistoryDeleteOption.DELETE_NOTHING);

    log.info("response: {}", historyExcerpt);
    assertThat(historyExcerpt).isEmpty();

    // Configure OcspResponder
    final int delayMilliseconds = 0;
    OcspResponderTestUtils.configure(
        "http://localhost:" + localServerPort,
        VALID_X509_EE_CERT,
        VALID_X509_ISSUER_CERT,
        certificateStatus,
        signer,
        delayMilliseconds);

    // Send Ocsp Request
    final HttpResponse<String> response =
        Unirest.post(ocspServiceUrlSeqNr42)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .body(ocspReq.getEncoded())
            .asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    // Expected is a history with at least one entry for serial number of VALID_X509_EE_CERT
    // here.

  }

  private void assertDeleteFullOcspRequestHistory(
      final Integer tslSeqNr, final BigInteger certSerialNr) throws IOException {

    initializeForHistory();

    {
      // Retrieve history for tslSeqNr and certSerialNr and assert that there is a history (for this
      // certificate)

      final List<OcspRequestHistoryEntryDto> historyExcerpt =
          retrieveHistoryExcerpt(tslSeqNr, certSerialNr, HistoryDeleteOption.DELETE_NOTHING);

      assertThat(historyExcerpt).isNotEmpty();

      // can be "null"
      final String certSerialNrStr = "" + certSerialNr;
      final List<OcspRequestHistoryEntryDto> historyExcerptFromStr =
          retrieveHistoryExcerptStr(
              String.valueOf(tslSeqNr),
              certSerialNrStr,
              HistoryDeleteOption.DELETE_NOTHING.toString());
      assertThat(historyExcerptFromStr).isNotEmpty();

      assertThatList(historyExcerpt).isEqualTo(historyExcerptFromStr);
    }

    {
      // Retrieve history for tslSeqNr and imaginary certificate, delete full history and assert
      // that there is no history

      final List<OcspRequestHistoryEntryDto> historyExcerpt =
          retrieveHistoryExcerpt(
              imaginaryNumber,
              BigInteger.valueOf(imaginaryNumber),
              HistoryDeleteOption.DELETE_FULL_HISTORY);
      assertThat(historyExcerpt).isEmpty();
    }

    {
      // Retrieve history for tslSeqNr and certSerialNr and assert that there is no history
      final List<OcspRequestHistoryEntryDto> historyExcerpt =
          retrieveHistoryExcerpt(tslSeqNr, certSerialNr, HistoryDeleteOption.DELETE_NOTHING);
      assertThat(historyExcerpt).isEmpty();
    }
  }

  /**
   * Configure OcspResponder, Send Ocsp Request, Send InfoRequest, deserialize response, assert that
   * there is a history Delete full history via InfoRequest and check
   */
  @Test
  void deleteFullOcspRequestHistory() throws IOException {
    log.info("deleteFullOcspRequestHistory: start");
    assertDeleteFullOcspRequestHistory(
        tslSeqNrFromOcspRequest, VALID_X509_EE_CERT.getSerialNumber());

    assertDeleteFullOcspRequestHistory(
        tslSeqNrFromOcspRequest, OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);
    assertDeleteFullOcspRequestHistory(tslSeqNrFromOcspRequest, null);

    assertDeleteFullOcspRequestHistory(
        OcspResponderManager.IGNORE_SEQUENCE_NUMBER, VALID_X509_EE_CERT.getSerialNumber());
    assertDeleteFullOcspRequestHistory(null, VALID_X509_EE_CERT.getSerialNumber());
    log.info("deleteFullOcspRequestHistory: end");
  }

  private void assertOcspRequestHistoryForCertificate(
      final Integer tslSeqNr, final BigInteger certSerialNr) throws IOException {
    initializeForHistory();

    {
      // Retrieve history for VALID_X509_EE_CERT and assert that there is a history (for this
      // certificate)

      final List<OcspRequestHistoryEntryDto> historyExcerpt1 =
          retrieveHistoryExcerpt(tslSeqNr, certSerialNr, HistoryDeleteOption.DELETE_NOTHING);

      assertThat(historyExcerpt1).isNotEmpty();

      final List<OcspRequestHistoryEntryDto> historyExcerptStr1 =
          retrieveHistoryExcerptStr(
              String.valueOf(tslSeqNr),
              "" + certSerialNr,
              HistoryDeleteOption.DELETE_NOTHING.toString());

      assertThat(historyExcerptStr1).isNotEmpty();

      assertThatList(historyExcerpt1).isEqualTo(historyExcerptStr1);
    }
    {
      // Retrieve history for imaginary tslSeqNr and certSerialNr, delete full history and assert
      // that there is no history
      final List<OcspRequestHistoryEntryDto> historyExcerpt2 =
          retrieveHistoryExcerpt(
              imaginaryNumber,
              BigInteger.valueOf(imaginaryNumber),
              HistoryDeleteOption.DELETE_QUERIED_HISTORY);
      assertThat(historyExcerpt2).isEmpty();
    }

    {
      // Retrieve history for tslSeqNr and certSerialNr and assert that there is no history
      final List<OcspRequestHistoryEntryDto> historyExcerpt3 =
          retrieveHistoryExcerpt(tslSeqNr, certSerialNr, HistoryDeleteOption.DELETE_NOTHING);
      assertThat(historyExcerpt3).isNotEmpty();

      final List<OcspRequestHistoryEntryDto> historyExcerptStr3 =
          retrieveHistoryExcerptStr(
              String.valueOf(tslSeqNr),
              "" + certSerialNr,
              HistoryDeleteOption.DELETE_NOTHING.toString());
      assertThat(historyExcerptStr3).isNotEmpty();

      assertThatList(historyExcerpt3).isEqualTo(historyExcerptStr3);
    }
    {
      // Retrieve history for tslSeqNr and certSerialNr, delete certificate history and assert that
      // there is history

      final List<OcspRequestHistoryEntryDto> historyExcerpt4 =
          retrieveHistoryExcerpt(
              tslSeqNr, certSerialNr, HistoryDeleteOption.DELETE_QUERIED_HISTORY);
      assertThat(historyExcerpt4).isNotEmpty();
    }
    {
      // Retrieve history for tslSeqNr and certSerialNr and assert that there is no history
      final List<OcspRequestHistoryEntryDto> historyExcerpt5 =
          retrieveHistoryExcerpt(tslSeqNr, certSerialNr, HistoryDeleteOption.DELETE_NOTHING);
      assertThat(historyExcerpt5).isEmpty();
    }
  }

  /**
   * Configure OcspResponder, Send Ocsp Request, Send InfoRequest, deserialize response, assert that
   * there is a history, Delete history for certificate via InfoRequest and check
   */
  @Test
  void deleteOcspRequestHistoryForCertificate() throws IOException {
    assertOcspRequestHistoryForCertificate(
        tslSeqNrFromOcspRequest, VALID_X509_EE_CERT.getSerialNumber());

    assertOcspRequestHistoryForCertificate(
        tslSeqNrFromOcspRequest, OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);
    assertOcspRequestHistoryForCertificate(tslSeqNrFromOcspRequest, null);

    assertOcspRequestHistoryForCertificate(
        OcspResponderManager.IGNORE_SEQUENCE_NUMBER, VALID_X509_EE_CERT.getSerialNumber());
    assertOcspRequestHistoryForCertificate(null, VALID_X509_EE_CERT.getSerialNumber());
  }

  /**
   * Retrieve an excerpt of the Ocsp request history for a certificate. Send InfoRequest and
   * deserialize response.
   *
   * @param tslSeqNr
   * @param certSerialNr
   * @param historyDeleteOption
   * @return historyExcerpt as list
   */
  private List<OcspRequestHistoryEntryDto> retrieveHistoryExcerpt(
      final Integer tslSeqNr,
      final BigInteger certSerialNr,
      final HistoryDeleteOption historyDeleteOption) {

    final OcspInfoRequestDto ocspInfoRequestDto =
        new OcspInfoRequestDto(tslSeqNr, certSerialNr, historyDeleteOption);

    log.info("sending {}", ocspInfoRequestDto);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(ocspInfoRequestDto);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(ocspInfoUrl, requestBodyAsJson);

    return PkitsCommonUtils.convertToList(responseBodyAsJson, OcspRequestHistoryEntryDto.class);
  }

  /**
   * Retrieve an excerpt of the Ocsp request history for a certificate. Send InfoRequest and
   * deserialize response.
   *
   * @param tslSeqNr
   * @param certSerialNr
   * @param historyDeleteOption
   * @return historyExcerpt as list
   */
  private List<OcspRequestHistoryEntryDto> retrieveHistoryExcerptStr(
      final String tslSeqNr, final String certSerialNr, final String historyDeleteOption) {

    final String requestBodyAsJson =
        """
            {
                "tslSeqNr": %s,
                "certSerialNr": %s,
                "historyDeleteOption": "%s"
            }
            """
            .formatted(tslSeqNr, certSerialNr, historyDeleteOption);

    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(ocspInfoUrl, requestBodyAsJson);

    return PkitsCommonUtils.convertToList(responseBodyAsJson, OcspRequestHistoryEntryDto.class);
  }
}
