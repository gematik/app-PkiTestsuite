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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import lombok.NonNull;

public class OcspResponderTestUtils {

  public static OcspRequestHistoryEntryDto getEntry(final int seqNr, final String certSerialNr) {
    return new OcspRequestHistoryEntryDto(
        seqNr, new BigInteger(certSerialNr), ZonedDateTime.now().toString());
  }

  public static void configure(
      final String uri,
      @NonNull final X509Certificate eeCert,
      final CustomCertificateStatusDto certificateStatus,
      @NonNull final P12Container signer,
      final int delayMilliseconds) {

    final OcspResponderConfigDto ocspResponderConfigDto =
        OcspResponderConfigDto.builder()
            .eeCert(eeCert)
            .certificateStatus(certificateStatus)
            .signer(signer)
            .delayMilliseconds(delayMilliseconds)
            .build();

    OcspResponderManager.configure(uri, ocspResponderConfigDto);
  }
}
