/*
 *  Copyright 2023 gematik GmbH
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

import static de.gematik.pki.pkits.common.PkitsCommonUtils.objectToBytes;
import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import org.apache.http.HttpStatus;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
class OcspConfigControllerTest {

  @LocalServerPort private int localServerPort;

  @Autowired private OcspResponseConfigHolder ocspResponseConfigHolder;

  private P12Container signer;
  private final X509Certificate eeCert =
      CertReader.readX509(
          Path.of("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));
  private final X509Certificate issuerCert =
      CertReader.readX509(
          Path.of("src/test/resources/certificates/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem"));

  OcspConfigControllerTest() {}

  @BeforeEach
  public void before() {
    invalidateOcspRespConfiguration();
  }

  @Test
  void ocspConfigNew() {
    final String WEBSERVER_CONFIG_URL =
        "http://localhost:" + localServerPort + WEBSERVER_CONFIG_ENDPOINT;

    final CertificateStatus certificateStatus = CertificateStatus.GOOD;
    final OcspResponderConfigDto ocspResponderConfig =
        OcspResponderConfigDto.builder().eeCert(eeCert).signer(signer).build();

    final String jsonContent =
        PkitsCommonUtils.createJsonContent(objectToBytes(ocspResponderConfig));
    final HttpResponse<String> response =
        Unirest.post(WEBSERVER_CONFIG_URL).body(jsonContent).asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(ocspResponseConfigHolder.getOcspResponderConfigDto().getEeCert().getSerialNumber())
        .isEqualTo(eeCert.getSerialNumber());
    assertThat(ocspResponseConfigHolder.getOcspResponderConfigDto().getCertificateStatus())
        .isEqualTo(certificateStatus);
  }

  private void invalidateOcspRespConfiguration() {

    signer =
        P12Reader.getContentFromP12(
            PkitsCommonUtils.readContent("src/test/resources/certificates/eccOcspSigner.p12"),
            "00");
    final OcspResponderConfigDto ocspResponderConfigDto =
        OcspResponderConfigDto.builder()
            .eeCert(issuerCert)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .signer(signer)
            .build();

    ocspResponseConfigHolder.setOcspResponderConfigDto(ocspResponderConfigDto);
  }

  @Test
  void serializeAndDeserializeOcspConfigReqDto() throws IOException {
    signer =
        P12Reader.getContentFromP12(
            PkitsCommonUtils.readContent("src/test/resources/certificates/eccOcspSigner.p12"),
            "00");
    // make config to serialize
    final OcspResponderConfigDto ocspResponderConfig =
        OcspResponderConfigDto.builder()
            .eeCert(issuerCert)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .signer(signer)
            .build();

    // serialize

    final byte[] ba = objectToBytes(ocspResponderConfig);
    final String jsonContent = PkitsCommonUtils.createJsonContent(ba);
    // deserialize
    final byte[] dtoBytes = new ObjectMapper().readValue(jsonContent, byte[].class);
    assertThat(dtoBytes).isNotEmpty();
    assertThat(dtoBytes).isEqualTo(ba);
  }
}
