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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.CustomCertificateStatusDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.NonNull;

public class OcspResponderTestUtils {

  public static X509Certificate getValidEeCert(final String filename) {
    return CertReader.readX509(
        ResourceReader.getFileFromResourceAsBytes(
            "certificates/GEM.SMCB-CA10/valid/" + filename, OcspResponderTestUtils.class));
  }

  public static X509Certificate getValidIssuerCert() {
    return CertReader.readX509(
        ResourceReader.getFileFromResourceAsBytes(
            "certificates/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem",
            OcspResponderTestUtils.class));
  }

  public static P12Container getSigner() {
    return P12Reader.getContentFromP12(
        ResourceReader.getFilePathFromResources(
            "certificates/eccOcspSigner.p12", OcspResponderTestUtils.class),
        PkitsTestDataConstants.KEYSTORE_PASSWORD);
  }

  public static X509Certificate getSignerCaCert() {
    return CertReader.readX509(
        ResourceReader.getFileFromResourceAsBytes(
            "certificates/GEM.EGK-CA57/GEM.EGK-CA57-TEST-ONLY.pem", OcspResponderTestUtils.class));
  }

  public static OcspRequestHistoryEntryDto getEntry(final int tslSeqNr, final String certSerialNr) {
    return new OcspRequestHistoryEntryDto(
        tslSeqNr, new BigInteger(certSerialNr), ZonedDateTime.now().toString(), null);
  }

  public static void configure(
      final String uri,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert,
      final CustomCertificateStatusDto certificateStatus,
      @NonNull final P12Container signer,
      final int delayMilliseconds) {

    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .certificateStatus(certificateStatus)
                        .signer(signer)
                        .delayMilliseconds(delayMilliseconds)
                        .build()))
            .build();

    OcspResponderManager.configure(uri, ocspResponderConfig);
  }

  public static void configureWithSignerCa(
      final String uri,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert,
      final CustomCertificateStatusDto certificateStatus,
      @NonNull final P12Container signer,
      @NonNull final X509Certificate signerCaCert,
      final int delayMilliseconds) {

    final OcspResponderConfig ocspResponderConfig =
        OcspResponderConfig.builder()
            .certificateDtos(
                List.of(
                    CertificateDto.builder()
                        .eeCert(eeCert)
                        .issuerCert(issuerCert)
                        .certificateStatus(certificateStatus)
                        .signer(signer)
                        .signerCaCert(signerCaCert)
                        .delayMilliseconds(delayMilliseconds)
                        .build()))
            .build();

    OcspResponderManager.configure(uri, ocspResponderConfig);
  }

  public static void clear(final String uri) {
    OcspResponderManager.clear(uri);
  }
}
