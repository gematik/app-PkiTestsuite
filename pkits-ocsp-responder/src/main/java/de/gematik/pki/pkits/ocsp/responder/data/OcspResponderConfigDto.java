/*
 * Copyright (c) 2022 gematik GmbH
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

import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkiCommonException;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.io.Serial;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;

@Builder
@Getter
public class OcspResponderConfigDto implements Serializable {

  @Serial private static final long serialVersionUID = -343495181812214884L;
  @NonNull private X509Certificate eeCert;
  @NonNull private P12Container signer;

  @Builder.Default private final boolean validCertHash = true;
  @Builder.Default private final boolean withCertHash = true;
  @Builder.Default private final boolean validSignature = true;

  @Builder.Default private final boolean validCertId = true;
  @Builder.Default private final int delayMilliseconds = 0;
  @Builder.Default private final OCSPRespStatus respStatus = OCSPRespStatus.SUCCESSFUL;
  @Builder.Default private final boolean withResponseBytes = true;

  @Builder.Default
  private final OcspResponseGenerator.ResponderIdType responderIdType = ResponderIdType.BY_KEY;

  @Builder.Default private final int thisUpdateDeltaMilliseconds = 0;
  @Builder.Default private final int producedAtDeltaMilliseconds = 0;

  /** if nextUpdateDeltaMilliseconds is null, then nextUpdate is set to null */
  @Builder.Default private final Integer nextUpdateDeltaMilliseconds = 0;

  @Builder.Default private final boolean withNullParameterHashAlgoOfCertId = false;

  // CertificateStatus is not serializable: for this reason we have to use
  // CustomCertificateStatusDto
  @Builder.Default
  private final CustomCertificateStatusDto certificateStatus =
      CustomCertificateStatusDto.createGood();

  public CustomCertificateStatusDto getCertificateStatusDto() {
    return certificateStatus;
  }

  public CertificateStatus getCertificateStatus() {
    if (certificateStatus == null) {
      throw new PkiCommonException("certificateStatus is not set");
    }
    return certificateStatus.getAsCertificateStatus();
  }

  public enum CustomCertificateStatusType {
    GOOD,
    UNKNOWN,
    REVOKED
  }

  public static final class CustomCertificateStatusDto implements Serializable {

    @Serial private static final long serialVersionUID = 3759865183639822586L;

    private final CustomCertificateStatusType type;
    private ZonedDateTime revokedDate;
    private int revokedReason;

    private CustomCertificateStatusDto(final CustomCertificateStatusType type) {
      this.type = type;
    }

    private CustomCertificateStatusDto(final ZonedDateTime revokedDate, final int revokedReason) {
      type = CustomCertificateStatusType.REVOKED;
      this.revokedDate = revokedDate;
      this.revokedReason = revokedReason;
    }

    public static CustomCertificateStatusDto createGood() {
      return new CustomCertificateStatusDto(CustomCertificateStatusType.GOOD);
    }

    public static CustomCertificateStatusDto createUnknown() {
      return new CustomCertificateStatusDto(CustomCertificateStatusType.UNKNOWN);
    }

    public static CustomCertificateStatusDto createRevoked(
        @NonNull final ZonedDateTime revokeDate, final int revokeReason) {
      return new CustomCertificateStatusDto(revokeDate, revokeReason);
    }

    public static CustomCertificateStatusDto create(
        final CustomCertificateStatusType customCertificateStatusType) {

      switch (customCertificateStatusType) {
        case UNKNOWN -> {
          return createUnknown();
        }
        case REVOKED -> {
          return createRevoked(ZonedDateTime.now(), CRLReason.aACompromise);
        }
        default -> {
          return createGood();
        }
      }
    }

    public boolean isGood() {
      return type == CustomCertificateStatusType.GOOD;
    }

    public boolean isUnknown() {
      return type == CustomCertificateStatusType.UNKNOWN;
    }

    public boolean isRevoked() {
      return type == CustomCertificateStatusType.REVOKED;
    }

    public CertificateStatus getAsCertificateStatus() {
      if (isGood()) {
        return CertificateStatus.GOOD;
      } else if (isUnknown()) {
        return new UnknownStatus();
      } else if (isRevoked()) {
        return new RevokedStatus(Date.from(revokedDate.toInstant()), revokedReason);
      }

      throw new PkiCommonException(
          "Cannot convert CustomCertificateStatusDto to CertificateStatus: wrong type");
    }

    @Override
    public String toString() {
      return "CustomCertificateStatusDto{type=%s, revokedDate=%s, revokedReason=%d}"
          .formatted(type, revokedDate, revokedReason);
    }
  }

  @Override
  public String toString() {
    return ("OcspResponderConfigDto{certSerialNr=%s, signerCN=%s, validCertHash=%s,"
            + " withCertHash=%s, validSignature=%s, validCertId=%s, certificateStatus=%s,"
            + " respStatus=%s, withResponseBytes=%s, thisUpdateDeltaMilliseconds=%s,"
            + " producedAtDeltaMilliseconds=%s, nextUpdateDeltaMilliseconds=%s,"
            + " withNullParameterHashAlgoOfCertId=%s}")
        .formatted(
            eeCert.getSerialNumber(),
            signer.getCertificate().getSubjectX500Principal().getName(),
            validCertHash,
            withCertHash,
            validSignature,
            validCertId,
            certificateStatus,
            respStatus,
            withResponseBytes,
            thisUpdateDeltaMilliseconds,
            producedAtDeltaMilliseconds,
            nextUpdateDeltaMilliseconds,
            withNullParameterHashAlgoOfCertId);
  }
}
