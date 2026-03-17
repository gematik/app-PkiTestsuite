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

package de.gematik.pki.pkits.ocsp.responder.data;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.CertReader;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.P12Container;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.ocsp.responder.controllers.OcspResponderTestUtils;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

class OcspResponderConfigTest {

  void assertGood(final OcspResponderConfig config) {
    assertThat(config.getCertificateDtos().getFirst().getOcspCertificateStatus())
        .isEqualTo(CertificateStatus.GOOD);
    assertThat(config.getCertificateDtos().getFirst().getCertificateStatusDto().isGood()).isTrue();
  }

  void assertUnknown(final OcspResponderConfig config) {
    assertThat(config.getCertificateDtos().getFirst().getOcspCertificateStatus())
        .isInstanceOf(UnknownStatus.class);
    assertThat(config.getCertificateDtos().getFirst().getCertificateStatusDto().isUnknown())
        .isTrue();
  }

  void assertRevoked(final OcspResponderConfig config, final ZonedDateTime revokedDate) {

    final CertificateStatus certificateStatus =
        config.getCertificateDtos().getFirst().getOcspCertificateStatus();
    assertThat(certificateStatus).isInstanceOf(RevokedStatus.class);
    assertThat(config.getCertificateDtos().getFirst().getCertificateStatusDto().isRevoked())
        .isTrue();

    final RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
    assertThat(revokedStatus.getRevocationReason()).isEqualTo(1);

    assertThat(revokedStatus.getRevocationTime()).isCloseTo(revokedDate.toInstant(), 1000);
  }

  @Test
  void getCustomCertificateStatusDto() {
    final X509Certificate eeCert = OcspResponderTestUtils.getValidEeCert("DrMedGunther.pem");

    final X509Certificate issuerCert = CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

    final P12Container signer = OcspResponderTestUtils.getSigner();

    assertGood(
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .signer(signer)
                        .certificateStatus(CustomCertificateStatusDto.createGood())
                        .build()))
            .build());

    assertUnknown(
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .signer(signer)
                        .certificateStatus(CustomCertificateStatusDto.createUnknown())
                        .build()))
            .build());

    final ZonedDateTime revokedDate = ZonedDateTime.now();

    assertRevoked(
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .signer(signer)
                        .certificateStatus(CustomCertificateStatusDto.createRevoked(revokedDate, 1))
                        .build()))
            .build(),
        revokedDate);
  }

  void assertSerializeAndDeserializeOcspConfig(final OcspResponderConfig ocspResponderConfig) {

    final OcspResponderConfigJsonDto jsonDto = ocspResponderConfig.toJsonDto();
    // serialize
    final String jsonContent = PkitsCommonUtils.createJsonContent(jsonDto);

    System.out.println("JSON Content: " + jsonContent);
    // deserialize
    final OcspResponderConfigJsonDto jsonDtoBack =
        JsonMapper.builder().build().readValue(jsonContent, OcspResponderConfigJsonDto.class);

    final OcspResponderConfig ocspResponderConfigBack = jsonDtoBack.toConfig();
    assertThat(ocspResponderConfigBack).hasToString(ocspResponderConfig.toString());
  }

  @Test
  void serializeAndDeserializeOcspConfigReqDto() {

    final X509Certificate eeCert = OcspResponderTestUtils.getValidEeCert("DrMedGunther.pem");

    final X509Certificate issuerCert = CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

    final P12Container signer = OcspResponderTestUtils.getSigner();

    // make config to serialize
    OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .certificateStatus(CustomCertificateStatusDto.createUnknown())
                        .signer(signer)
                        .build()))
            .build();

    assertSerializeAndDeserializeOcspConfig(ocspResponderConfig);

    ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .certificateStatus(
                            CustomCertificateStatusDto.createRevoked(
                                GemLibPkiUtils.now().plusYears(1), 100))
                        .signer(signer)
                        .build()))
            .build();

    assertSerializeAndDeserializeOcspConfig(ocspResponderConfig);
  }

  @Test
  void serializeAndDeserializeOcspConfigReqDto_delayMilliseconds() {

    final X509Certificate eeCert = OcspResponderTestUtils.getValidEeCert("DrMedGunther.pem");

    final X509Certificate issuerCert = CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

    final P12Container signer = OcspResponderTestUtils.getSigner();

    // make config to serialize
    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .certificateStatus(CustomCertificateStatusDto.createGood())
                        .signer(signer)
                        .delayMilliseconds(4242)
                        .build()))
            .build();

    assertSerializeAndDeserializeOcspConfig(ocspResponderConfig);
  }

  @Test
  void testCertificateJsonDtoDeserialization() {
    final String json =
        """
        {
          "delayMilliseconds": 4242,
          "attachIssuerCert": false,
          "validSignature": true,
          "validCertHash": true,
          "withCertHash": true,
          "withNullParameterHashAlgoOfCertId": false,
          "withResponseBytes": true
        }
        """;

    final ObjectMapper mapper =
        JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    final CertificateJsonDto dto = mapper.readValue(json, CertificateJsonDto.class);

    System.out.println("Deserialized delayMilliseconds: " + dto.getDelayMilliseconds());

    assertThat(dto.getDelayMilliseconds()).isEqualTo(4242);
  }

  @Test
  void testCustomCertificateStatusDtoDeserialization() {
    final String json =
        """
        {
          "type": "UNKNOWN",
          "revokedDate": null,
          "revokedReason": 0
        }
        """;

    final ObjectMapper mapper =
        JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    final CustomCertificateStatusDto dto = mapper.readValue(json, CustomCertificateStatusDto.class);

    assertThat(dto.getType()).isEqualTo(CustomCertificateStatusType.UNKNOWN);
    assertThat(dto.isUnknown()).isTrue();
  }
}
