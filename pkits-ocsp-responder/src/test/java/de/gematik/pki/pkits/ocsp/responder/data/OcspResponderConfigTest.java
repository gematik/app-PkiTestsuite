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

package de.gematik.pki.pkits.ocsp.responder.data;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.ocsp.responder.controllers.OcspResponderTestUtils;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.Test;

class OcspResponderConfigTest {

  void assertGood(final OcspResponderConfig config) {
    assertThat(config.getOcspCertificateStatus()).isEqualTo(CertificateStatus.GOOD);
    assertThat(config.getCertificateStatusDto().isGood()).isTrue();
  }

  void assertUnknown(final OcspResponderConfig config) {
    assertThat(config.getOcspCertificateStatus()).isInstanceOf(UnknownStatus.class);
    assertThat(config.getCertificateStatusDto().isUnknown()).isTrue();
  }

  void assertRevoked(final OcspResponderConfig config, final ZonedDateTime revokedDate) {

    final CertificateStatus certificateStatus = config.getOcspCertificateStatus();
    assertThat(certificateStatus).isInstanceOf(RevokedStatus.class);
    assertThat(config.getCertificateStatusDto().isRevoked()).isTrue();

    final RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
    assertThat(revokedStatus.getRevocationReason()).isEqualTo(1);

    assertThat(revokedStatus.getRevocationTime()).isCloseTo(revokedDate.toInstant(), 1000);
  }

  @Test
  void getCustomCertificateStatusDto() {
    final X509Certificate eeCert = OcspResponderTestUtils.getValidEeCert();

    final X509Certificate issuerCert = CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

    final P12Container signer = OcspResponderTestUtils.getSigner();

    assertGood(
        OcspResponderConfig.builder()
            .eeCert(eeCert)
            .issuerCert(issuerCert)
            .signer(signer)
            .certificateStatus(CustomCertificateStatusDto.createGood())
            .build());

    assertUnknown(
        OcspResponderConfig.builder()
            .eeCert(eeCert)
            .issuerCert(issuerCert)
            .signer(signer)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .build());

    final ZonedDateTime revokedDate = ZonedDateTime.now();

    assertRevoked(
        OcspResponderConfig.builder()
            .eeCert(eeCert)
            .issuerCert(issuerCert)
            .signer(signer)
            .certificateStatus(CustomCertificateStatusDto.createRevoked(revokedDate, 1))
            .build(),
        revokedDate);
  }

  void assertSerializeAndDeserializeOcspConfig(final OcspResponderConfig ocspResponderConfig)
      throws JsonProcessingException {

    final OcspResponderConfigJsonDto jsonDto = ocspResponderConfig.toJsonDto();
    // serialize
    final String jsonContent = PkitsCommonUtils.createJsonContent(jsonDto);

    // deserialize
    final OcspResponderConfigJsonDto jsonDtoBack =
        new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .readValue(jsonContent, OcspResponderConfigJsonDto.class);

    final OcspResponderConfig ocspResponderConfigBack = jsonDtoBack.toConfig();
    assertThat(ocspResponderConfigBack).hasToString(ocspResponderConfig.toString());
  }

  @Test
  void serializeAndDeserializeOcspConfigReqDto() throws IOException {

    final X509Certificate eeCert = OcspResponderTestUtils.getValidEeCert();

    final X509Certificate issuerCert = CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA);

    final P12Container signer = OcspResponderTestUtils.getSigner();

    // make config to serialize
    OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .eeCert(eeCert)
            .issuerCert(issuerCert)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .signer(signer)
            .build();

    assertSerializeAndDeserializeOcspConfig(ocspResponderConfig);

    ocspResponderConfig =
        OcspResponderConfig.builder()
            .eeCert(eeCert)
            .issuerCert(issuerCert)
            .certificateStatus(
                CustomCertificateStatusDto.createRevoked(GemLibPkiUtils.now().plusYears(1), 100))
            .signer(signer)
            .build();

    assertSerializeAndDeserializeOcspConfig(ocspResponderConfig);
  }
}
