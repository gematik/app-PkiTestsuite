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

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponseAlgoBehavior;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkiCommonException;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.security.cert.X509Certificate;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.experimental.SuperBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;

@SuperBuilder(toBuilder = true)
@Getter
@NoArgsConstructor
public class OcspResponderConfig {

  @JsonIgnore @NonNull protected X509Certificate eeCert;
  @JsonIgnore @NonNull protected X509Certificate issuerCert;
  @JsonIgnore @NonNull protected P12Container signer;
  @Builder.Default private final boolean validCertHash = true;
  @Builder.Default private final boolean withCertHash = true;
  @Builder.Default private final boolean validSignature = true;

  @Builder.Default
  private final CertificateIdGeneration certificateIdGeneration =
      CertificateIdGeneration.VALID_CERTID;

  @Builder.Default private final int delayMilliseconds = 0;
  @Builder.Default private final OCSPRespStatus respStatus = OCSPRespStatus.SUCCESSFUL;
  @Builder.Default private final boolean withResponseBytes = true;

  @Builder.Default private final ResponderIdType responderIdType = ResponderIdType.BY_KEY;

  @Builder.Default private final int thisUpdateDeltaMilliseconds = 0;
  @Builder.Default private final int producedAtDeltaMilliseconds = 0;

  /** if nextUpdateDeltaMilliseconds is null, then nextUpdate is set to null */
  @Builder.Default private final Integer nextUpdateDeltaMilliseconds = 0;

  @Builder.Default private final boolean withNullParameterHashAlgoOfCertId = false;
  @Builder.Default ResponseAlgoBehavior responseAlgoBehavior = ResponseAlgoBehavior.MIRRORING;

  // CertificateStatus is not serializable: for this reason we have to use
  // CustomCertificateStatusDto
  @Builder.Default
  private final CustomCertificateStatusDto certificateStatus =
      CustomCertificateStatusDto.createGood();

  public OcspResponderConfigJsonDto toJsonDto() {
    return new OcspResponderConfigJsonDto(this);
  }

  @JsonIgnore
  public CustomCertificateStatusDto getCertificateStatusDto() {
    return certificateStatus;
  }

  @JsonIgnore
  public CertificateStatus getOcspCertificateStatus() {
    if (certificateStatus == null) {
      throw new PkiCommonException("certificateStatus is not set");
    }
    return certificateStatus.getAsCertificateStatus();
  }

  @Override
  public String toString() {
    return ("OcspResponderConfig{eeCertSerialNr=%s, issuerSubjectCN=%s, signerCN=%s, "
            + " validCertHash=%s, withCertHash=%s, validSignature=%s,"
            + " certificateIdGeneration=%s, certificateStatus=%s, respStatus=%s,"
            + " withResponseBytes=%s, thisUpdateDeltaMilliseconds=%s,"
            + " producedAtDeltaMilliseconds=%s, nextUpdateDeltaMilliseconds=%s,"
            + " withNullParameterHashAlgoOfCertId=%s}")
        .formatted(
            eeCert.getSerialNumber(),
            issuerCert.getSubjectX500Principal().getName(),
            signer.getCertificate().getSubjectX500Principal().getName(),
            validCertHash,
            withCertHash,
            validSignature,
            certificateIdGeneration,
            certificateStatus,
            respStatus,
            withResponseBytes,
            thisUpdateDeltaMilliseconds,
            producedAtDeltaMilliseconds,
            nextUpdateDeltaMilliseconds,
            withNullParameterHashAlgoOfCertId);
  }
}
