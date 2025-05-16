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

package de.gematik.pki.pkits.ocsp.responder.data;

import static org.assertj.core.api.Assertions.within;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.Test;

class CustomCertificateStatusDtoTest {

  @Test
  void testCreateGood() {
    final CustomCertificateStatusDto certificateStatusDto =
        CustomCertificateStatusDto.create(CustomCertificateStatusType.GOOD);
    final CertificateStatus certificateStatus = certificateStatusDto.getAsCertificateStatus();
    assertThat(certificateStatus).isEqualTo(CertificateStatus.GOOD);
  }

  @Test
  void testCreateUnknown() {
    final CustomCertificateStatusDto certificateStatusDto =
        CustomCertificateStatusDto.create(CustomCertificateStatusType.UNKNOWN);
    final CertificateStatus certificateStatus = certificateStatusDto.getAsCertificateStatus();
    assertThat(certificateStatus).isInstanceOf(UnknownStatus.class);
  }

  @Test
  void testCreateRevoked() {
    final CustomCertificateStatusDto certificateStatusDto =
        CustomCertificateStatusDto.create(CustomCertificateStatusType.REVOKED);
    final CertificateStatus certificateStatus = certificateStatusDto.getAsCertificateStatus();
    assertThat(certificateStatus).isInstanceOf(RevokedStatus.class);
    final RevokedStatus revokedStatus = (RevokedStatus) certificateStatus;
    final ZonedDateTime revocationTime =
        ZonedDateTime.ofInstant(revokedStatus.getRevocationTime().toInstant(), ZoneOffset.UTC);
    assertThat(revocationTime).isCloseTo(GemLibPkiUtils.now(), within(1, ChronoUnit.SECONDS));
    assertThat(revokedStatus.getRevocationReason()).isEqualTo(CRLReason.aACompromise);
  }
}
