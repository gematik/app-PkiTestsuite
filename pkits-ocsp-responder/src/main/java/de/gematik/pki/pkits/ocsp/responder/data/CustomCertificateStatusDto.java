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

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;
import com.fasterxml.jackson.annotation.JsonIgnore;
import de.gematik.pki.pkits.common.PkiCommonException;
import java.time.ZonedDateTime;
import java.util.Date;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;

@NoArgsConstructor
@Getter
@Setter
public final class CustomCertificateStatusDto {

  private CustomCertificateStatusType type;

  @JsonFormat(shape = Shape.STRING)
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

    return switch (customCertificateStatusType) {
      case UNKNOWN -> createUnknown();
      case REVOKED -> createRevoked(ZonedDateTime.now(), CRLReason.aACompromise);

        // CustomCertificateStatusType.GOOD
      default -> createGood();
    };
  }

  @JsonIgnore
  public boolean isGood() {
    return type == CustomCertificateStatusType.GOOD;
  }

  @JsonIgnore
  public boolean isUnknown() {
    return type == CustomCertificateStatusType.UNKNOWN;
  }

  @JsonIgnore
  public boolean isRevoked() {
    return type == CustomCertificateStatusType.REVOKED;
  }

  @JsonIgnore
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
