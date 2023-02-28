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

package de.gematik.pki.pkits.ocsp.responder.data;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.Test;

class OcspResponderConfigDtoTest {

  @Test
  void getCustomCertificateStatusDto() {
    final X509Certificate eeCert =
        CertReader.readX509(
            Path.of("src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));

    final P12Container signer =
        P12Reader.getContentFromP12(
            PkitsCommonUtils.readContent("src/test/resources/certificates/eccOcspSigner.p12"),
            "00");

    OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(eeCert)
            .signer(signer)
            .certificateStatus(CustomCertificateStatusDto.createGood())
            .build();
    assertThat(dto.getCertificateStatus()).isEqualTo(CertificateStatus.GOOD);
    assertThat(dto.getCertificateStatusDto().isGood()).isTrue();

    dto =
        OcspResponderConfigDto.builder()
            .eeCert(eeCert)
            .signer(signer)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .build();

    assertThat(dto.getCertificateStatus()).isInstanceOf(UnknownStatus.class);
    assertThat(dto.getCertificateStatusDto().isUnknown()).isTrue();

    final ZonedDateTime revokedDate = ZonedDateTime.now();
    dto =
        OcspResponderConfigDto.builder()
            .eeCert(eeCert)
            .signer(signer)
            .certificateStatus(CustomCertificateStatusDto.createRevoked(revokedDate, 1))
            .build();

    final CertificateStatus certificateStatus = dto.getCertificateStatus();
    assertThat(certificateStatus).isInstanceOf(RevokedStatus.class);
    assertThat(dto.getCertificateStatusDto().isRevoked()).isTrue();

    final RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
    assertThat(revokedStatus.getRevocationReason()).isEqualTo(1);

    assertThat(revokedStatus.getRevocationTime()).isCloseTo(revokedDate.toInstant(), 1000);
  }
}
