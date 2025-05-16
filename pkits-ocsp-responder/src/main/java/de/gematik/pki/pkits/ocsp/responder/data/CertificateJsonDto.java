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

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class CertificateJsonDto extends CertificateDto {

  @NonNull private String eeCertEncoded;
  @NonNull private String issuerCertEncoded;
  @NonNull private String signerCertificateEncoded;
  @NonNull private String signerPrivateKeyEncoded;

  public CertificateJsonDto(final CertificateDto certificateDto) {
    super(certificateDto.toBuilder());

    this.eeCertEncoded = GemLibPkiUtils.toMimeBase64NoLineBreaks(this.getEeCert());
    this.issuerCertEncoded = GemLibPkiUtils.toMimeBase64NoLineBreaks(this.getIssuerCert());
    this.signerCertificateEncoded =
        GemLibPkiUtils.toMimeBase64NoLineBreaks(this.getSigner().getCertificate());
    this.signerPrivateKeyEncoded =
        GemLibPkiUtils.toMimeBase64NoLineBreaks(this.getSigner().getPrivateKey().getEncoded());
  }

  public CertificateDto toCertificateDto() {

    final X509Certificate eeCert =
        CertReader.readX509(GemLibPkiUtils.decodeFromMimeBase64(this.eeCertEncoded));

    final X509Certificate issuerCert =
        CertReader.readX509(GemLibPkiUtils.decodeFromMimeBase64(this.issuerCertEncoded));

    final X509Certificate signerCert =
        CertReader.readX509(GemLibPkiUtils.decodeFromMimeBase64(this.signerCertificateEncoded));

    final PrivateKey signerPrivateKey =
        GemLibPkiUtils.convertPrivateKey(this.signerPrivateKeyEncoded);

    this.eeCert = eeCert;
    this.issuerCert = issuerCert;
    this.signer = new P12Container(signerCert, signerPrivateKey);

    return this;
  }
}
