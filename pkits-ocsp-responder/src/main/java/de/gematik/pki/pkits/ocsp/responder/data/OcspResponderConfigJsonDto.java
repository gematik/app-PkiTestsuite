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

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class OcspResponderConfigJsonDto extends OcspResponderConfig {

  @NonNull private String eeCertEncoded;
  @NonNull private String issuerCertEncoded;
  @NonNull private String signerCertificateEncoded;
  @NonNull private String signerPrivateKeyEncoded;

  public OcspResponderConfigJsonDto(final OcspResponderConfig config) {
    super(config.toBuilder());

    this.eeCertEncoded = GemLibPkiUtils.toMimeBase64NoLineBreaks(eeCert);
    this.issuerCertEncoded = GemLibPkiUtils.toMimeBase64NoLineBreaks(issuerCert);

    this.signerCertificateEncoded =
        GemLibPkiUtils.toMimeBase64NoLineBreaks(signer.getCertificate());

    this.signerPrivateKeyEncoded =
        GemLibPkiUtils.toMimeBase64NoLineBreaks(signer.getPrivateKey().getEncoded());
  }

  public OcspResponderConfig toConfig() {

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
