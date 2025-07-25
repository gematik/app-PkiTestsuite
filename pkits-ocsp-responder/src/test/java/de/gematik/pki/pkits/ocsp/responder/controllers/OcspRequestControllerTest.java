/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_REQUEST;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_RESPONSE;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static org.apache.hc.core5.http.HttpHeaders.ACCEPT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@Slf4j
@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
class OcspRequestControllerTest {

  private static final CustomCertificateStatusDto CERT_STATUS_GOOD =
      CustomCertificateStatusDto.createGood();
  private static P12Container signer;
  private static X509Certificate VALID_X509_EE_CERT;
  private static X509Certificate VALID_X509_ISSUER_CERT;
  private static OCSPReq ocspReq;
  @LocalServerPort private int localServerPort;
  private int delayMilliseconds = 0;

  @Autowired private OcspRequestHistory ocspRequestHistory;
  private String ocspServiceUrl;
  String ocspServiceUrlSeqNr31;

  @BeforeAll
  public static void setup() {
    VALID_X509_EE_CERT = OcspResponderTestUtils.getValidEeCert("DrMedGunther.pem");
    VALID_X509_ISSUER_CERT = OcspResponderTestUtils.getValidIssuerCert();
    signer = OcspResponderTestUtils.getSigner();
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
  }

  private String getLocalhostEndpoint(final String endpoint) {
    return "http://localhost:" + localServerPort + endpoint;
  }

  @BeforeEach
  public void init() {
    ocspServiceUrl = getLocalhostEndpoint(OCSP_SSP_ENDPOINT);
    ocspServiceUrlSeqNr31 = ocspServiceUrl + "/310000";
    delayMilliseconds = 0;
    OcspResponderTestUtils.configure(
        getLocalhostEndpoint(""),
        VALID_X509_EE_CERT,
        VALID_X509_ISSUER_CERT,
        CERT_STATUS_GOOD,
        signer,
        delayMilliseconds);
    log.info("OCSP Request TX: {}", ocspReq.getRequestList()[0].getCertID().getSerialNumber());
  }

  @Test
  void checkHttpStatusOk() throws IOException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .body(ocspReq.getEncoded())
            .asBytes();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
  }

  @ParameterizedTest
  @ValueSource(strings = {"/invalid", "/4a"})
  void checkHttpStatus400(final String str) throws IOException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrl + str)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_BAD_REQUEST);
  }

  @ParameterizedTest
  @ValueSource(strings = {"invalid", "/4/a", "/4/3"})
  void checkHttpStatus404(final String str) throws IOException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrl + str)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
  }

  @Test
  void checkHttpContentTypeOk() throws IOException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
  }

  @Test
  void checkHttpContentTypeNotAcceptable() throws IOException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .body(ocspReq.getEncoded())
            .asBytes();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_ACCEPTABLE);
  }

  @Test
  void checkOcspResponseStatusOk() throws IOException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    final OCSPResp ocspResp = new OCSPResp(response.getBody());
    assertThat(ocspResp.getStatus()).isEqualTo(OCSPResp.SUCCESSFUL);
  }

  @Test
  void checkOcspResponseExtensions() throws IOException, OCSPException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    final OCSPResp ocspResp = new OCSPResp(response.getBody());
    final BasicOCSPResp ocspResponse = (BasicOCSPResp) ocspResp.getResponseObject();
    assertThat(ocspResponse.hasExtensions()).isTrue();
    assertThat(ocspResponse.getExtensionOIDs()).hasSize(1);
    assertThat(ocspResponse.getExtensionOIDs()).contains(id_isismtt_at_certHash);
  }

  @Test
  void shouldNotIncludeCertHashExtensionInResponse() throws IOException, OCSPException {
    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(VALID_X509_EE_CERT)
                        .issuerCert(VALID_X509_ISSUER_CERT)
                        .certificateStatus(CERT_STATUS_GOOD)
                        .withCertHash(false)
                        .signer(signer)
                        .delayMilliseconds(delayMilliseconds)
                        .build()))
            .build();

    OcspResponderManager.configure(getLocalhostEndpoint(""), ocspResponderConfig);

    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    final OCSPResp ocspResp = new OCSPResp(response.getBody());
    final BasicOCSPResp ocspResponse = (BasicOCSPResp) ocspResp.getResponseObject();
    assertThat(ocspResponse.hasExtensions()).isFalse();
    assertThat(ocspResponse.getExtensionOIDs()).isEmpty();
  }

  @Test
  void checkOcspSingleResponseCertStatusGood() throws IOException, OCSPException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    final OCSPResp ocspResp = new OCSPResp(response.getBody());
    final SingleResp singleResp = ((BasicOCSPResp) ocspResp.getResponseObject()).getResponses()[0];
    assertThat(singleResp.getCertStatus()).isSameAs(CertificateStatus.GOOD);
  }

  @Test
  void checkOcspSingleResponseCertSerialNumber() throws IOException, OCSPException {
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    final OCSPResp ocspResp = new OCSPResp(response.getBody());

    final SingleResp singleResp = ((BasicOCSPResp) ocspResp.getResponseObject()).getResponses()[0];
    assertThat(singleResp.getCertID().getSerialNumber())
        .isEqualTo(VALID_X509_EE_CERT.getSerialNumber());
  }

  @Test
  void checkOcspHistorySize() throws IOException, OCSPException {
    assertThat(ocspRequestHistory).isNotNull();
    final int histSize = ocspRequestHistory.size();
    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    final OCSPResp ocspResp = new OCSPResp(response.getBody());
    final SingleResp singleResp = ((BasicOCSPResp) ocspResp.getResponseObject()).getResponses()[0];
    assertThat(singleResp.getCertStatus()).isSameAs(CertificateStatus.GOOD);
    assertThat(ocspRequestHistory.size()).isEqualTo(histSize + 1);
  }

  @Test
  void certSerialNrNotConfigured() throws IOException {

    OcspResponderTestUtils.configure(
        getLocalhostEndpoint(""),
        VALID_X509_ISSUER_CERT,
        VALID_X509_ISSUER_CERT,
        CERT_STATUS_GOOD,
        signer,
        delayMilliseconds);

    final HttpResponse<byte[]> response =
        Unirest.post(ocspServiceUrlSeqNr31)
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body(ocspReq.getEncoded())
            .asBytes();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  private long getMillisecondsDurationForCallWithDelay(final int customDelayMilliseconds)
      throws IOException {
    final ZonedDateTime start = ZonedDateTime.now();

    OcspResponderTestUtils.configure(
        getLocalhostEndpoint(""),
        VALID_X509_EE_CERT,
        VALID_X509_ISSUER_CERT,
        CERT_STATUS_GOOD,
        signer,
        customDelayMilliseconds);

    Unirest.post(ocspServiceUrlSeqNr31)
        .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
        .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
        .body(ocspReq.getEncoded())
        .asBytes();

    final ZonedDateTime end = ZonedDateTime.now();
    return Duration.between(start, end).toMillis();
  }

  @Test
  void checkDelayPositiveMilliseconds() throws IOException {
    final int customDelayMilliseconds = 10 * 1000;
    final long duration = getMillisecondsDurationForCallWithDelay(customDelayMilliseconds);
    assertThat(duration).isGreaterThan(customDelayMilliseconds);
  }

  @Test
  void checkDelayZeroMilliseconds() throws IOException {
    final int customDelayMilliseconds = 0;
    final long duration = getMillisecondsDurationForCallWithDelay(customDelayMilliseconds);
    assertThat(duration).isLessThan(1000);
  }
}
