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

import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_WEBSERVER_CONFIG_ENDPOINT;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponseAlgoBehavior;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigJsonDto;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
class OcspConfigControllerTest {

  @LocalServerPort private int localServerPort;

  @Autowired private OcspResponseConfigHolder ocspResponseConfigHolder;

  private P12Container signer;
  private final X509Certificate eeCert = OcspResponderTestUtils.getValidEeCert();
  private final X509Certificate issuerCert =
      CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

  OcspConfigControllerTest() {}

  @BeforeEach
  public void before() {
    invalidateOcspRespConfiguration();
  }

  @Test
  void ocspConfigNew() {
    final String WEBSERVER_CONFIG_URL =
        "http://localhost:" + localServerPort + OCSP_WEBSERVER_CONFIG_ENDPOINT;

    final CertificateStatus certificateStatus = CertificateStatus.GOOD;
    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder().eeCert(eeCert).issuerCert(issuerCert).signer(signer).build();

    final OcspResponderConfigJsonDto jsonDto = ocspResponderConfig.toJsonDto();
    final String jsonContent = PkitsCommonUtils.createJsonContent(jsonDto);

    final HttpResponse<String> response =
        Unirest.post(WEBSERVER_CONFIG_URL)
            .body(jsonContent)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(ocspResponseConfigHolder.getOcspResponderConfig().getEeCert().getSerialNumber())
        .isEqualTo(eeCert.getSerialNumber());
    assertThat(ocspResponseConfigHolder.getOcspResponderConfig().getOcspCertificateStatus())
        .isEqualTo(certificateStatus);
  }

  @Test
  void ocspConfigNewJsonStr() throws JsonProcessingException {
    final String WEBSERVER_CONFIG_URL =
        "http://localhost:" + localServerPort + OCSP_WEBSERVER_CONFIG_ENDPOINT;

    final String jsonContent =
        """
            {
              "validCertHash": false,
              "withCertHash": false,
              "validSignature": false,
              "certificateIdGeneration": "%s",
              "delayMilliseconds": 11,
              "respStatus": "%s",
              "withResponseBytes": false,
              "responderIdType": "%s",
              "thisUpdateDeltaMilliseconds": 22,
              "producedAtDeltaMilliseconds": 33,
              "nextUpdateDeltaMilliseconds": 44,
              "withNullParameterHashAlgoOfCertId": true,
              "responseAlgoBehavior": "%s",
              "certificateStatus": {
                "type": "REVOKED",
                "revokedDate": "2028-08-08T08:08:08.2665079Z",
                "revokedReason": 55
              },
              "eeCertEncoded": "%s",
              "issuerCertEncoded": "%s",
              "signerCertificateEncoded": "%s",
              "signerPrivateKeyEncoded": "%s"
            }
            """
            .formatted(
                CertificateIdGeneration.INVALID_CERTID_HASH_ALGO,
                OCSPRespStatus.TRY_LATER,
                ResponderIdType.BY_NAME,
                ResponseAlgoBehavior.SHA2,
                GemLibPkiUtils.toMimeBase64NoLineBreaks(eeCert),
                GemLibPkiUtils.toMimeBase64NoLineBreaks(issuerCert),
                GemLibPkiUtils.toMimeBase64NoLineBreaks(signer.getCertificate()),
                GemLibPkiUtils.toMimeBase64NoLineBreaks(signer.getPrivateKey().getEncoded()));

    final CustomCertificateStatusDto certificateStatusDto =
        CustomCertificateStatusDto.createRevoked(
            ZonedDateTime.parse("2028-08-08T08:08:08.2665079Z"), 55);

    final RevokedStatus expectedCertificateStatus =
        (RevokedStatus) certificateStatusDto.getAsCertificateStatus();

    final HttpResponse<String> response =
        Unirest.post(WEBSERVER_CONFIG_URL)
            .body(jsonContent)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(ocspResponseConfigHolder.getOcspResponderConfig().getEeCert().getSerialNumber())
        .isEqualTo(eeCert.getSerialNumber());

    final RevokedStatus actualCertificateStatus =
        (RevokedStatus)
            ocspResponseConfigHolder.getOcspResponderConfig().getOcspCertificateStatus();
    assertThat(actualCertificateStatus.getRevocationReason())
        .isEqualTo(expectedCertificateStatus.getRevocationReason());
    assertThat(actualCertificateStatus.getRevocationTime())
        .isEqualTo(expectedCertificateStatus.getRevocationTime());

    final OcspResponderConfigJsonDto expectedJsonDto =
        new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .readValue(jsonContent, OcspResponderConfigJsonDto.class);

    final OcspResponderConfig expectedConfig = expectedJsonDto.toConfig();
    final OcspResponderConfig actualConfig = ocspResponseConfigHolder.getOcspResponderConfig();
    assertThat(actualConfig).hasToString(expectedConfig.toString());
  }

  private void invalidateOcspRespConfiguration() {

    signer = OcspResponderTestUtils.getSigner();

    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .eeCert(issuerCert)
            .issuerCert(issuerCert)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .signer(signer)
            .build();

    ocspResponseConfigHolder.setOcspResponderConfig(ocspResponderConfig);
  }
}
