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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponderException;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class OcspRequestController {

  private final OcspRequestHistory ocspRequestHistory;
  private final OcspResponseConfigHolder ocspResponseConfigHolder;

  @PostMapping(
      value = OCSP_SSP_ENDPOINT + "/{seqNr}",
      produces = OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
  public byte[] ocspService(
      @PathVariable("seqNr") final int seqNr, final HttpServletRequest request) {
    final OCSPReq ocspReq = createOcspReqFromServletRequest(request);
    final BigInteger certSerialNr = getCertSerialNrFromRequest(ocspReq);
    if (!ocspResponseConfigHolder.isCertSerialNrConfigured(certSerialNr)) {
      log.error(
          "CertSerialNr {} is not configured. Configured is certSerialNr {}.",
          certSerialNr,
          ocspResponseConfigHolder.getOcspResponderConfigDto().getEeCert().getSerialNumber());
      throw new OcspResponderException("CertSerialNr is not configured");
    }
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(certSerialNr, ZonedDateTime.now().toString(), seqNr));
    log.info(
        "Build OCSP Response for certSerialNr {} and send to {}:{}",
        certSerialNr,
        request.getRemoteHost(),
        request.getRemotePort());

    final int delayMilliseconds =
        ocspResponseConfigHolder.getOcspResponderConfigDto().getDelayMilliseconds();

    if (delayMilliseconds < 0) {
      throw new PkiCommonException("delayMilliseconds is < 0");
    }

    if (delayMilliseconds > 0) {
      log.info("Delay building OCSP Response for {} milliseconds", delayMilliseconds);
      PkitsCommonUtils.waitMilliseconds(delayMilliseconds);
    }

    return buildOcspResponseBytes(ocspReq);
  }

  private byte[] buildOcspResponseBytes(final OCSPReq ocspReq) {
    final OcspResponderConfigDto dto = ocspResponseConfigHolder.getOcspResponderConfigDto();
    final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

    final OcspResponseGenerator ocspResponseGenerator =
        OcspResponseGenerator.builder()
            .signer(dto.getSigner())
            .withCertHash(dto.isWithCertHash())
            .validCertHash(dto.isValidCertHash())
            .validSignature(dto.isValidSignature())
            .validCertId(dto.isValidCertId())
            .responderIdType(dto.getResponderIdType())
            .respStatus(dto.getRespStatus())
            .withResponseBytes(dto.isWithResponseBytes())
            .thisUpdate(now.plus(dto.getThisUpdateDeltaMilliseconds(), ChronoUnit.MILLIS))
            .producedAt(now.plus(dto.getProducedAtDeltaMilliseconds(), ChronoUnit.MILLIS))
            .nextUpdate(now.plus(dto.getNextUpdateDeltaMilliseconds(), ChronoUnit.MILLIS))
            .withNullParameterHashAlgoOfCertId(dto.isWithNullParameterHashAlgoOfCertId())
            .build();
    try {
      final CertificateStatus certificateStatus = dto.getCertificateStatus();
      final byte[] ocspResponseBytes =
          ocspResponseGenerator.generate(ocspReq, dto.getEeCert(), certificateStatus).getEncoded();
      log.debug("Build OcspResponse done");
      return ocspResponseBytes;
    } catch (final IOException e) {
      throw new OcspResponderException("Could not create OcspResponse.", e);
    }
  }

  private OCSPReq createOcspReqFromServletRequest(final HttpServletRequest request) {

    try {
      final InputStream inputStream = request.getInputStream();
      if (inputStream != null) {
        final byte[] ocspRequestBytes = inputStream.readAllBytes();
        inputStream.close();
        return new OCSPReq(ocspRequestBytes);
      } else {
        throw new OcspResponderException("Could not read InputStream of HttpServletRequest.");
      }
    } catch (final IOException e) {
      throw new OcspResponderException("Could not get InputStream of HttpServletRequest.", e);
    }
  }

  private BigInteger getCertSerialNrFromRequest(final OCSPReq ocspReq) {
    final BigInteger certSerialNr = ocspReq.getRequestList()[0].getCertID().getSerialNumber();
    if (certSerialNr == null) {
      throw new OcspResponderException("Could not extract certSerialNr from OcspRequest.");
    }
    log.info("RX OCSP Request for certSerialNr: {}", certSerialNr);
    return certSerialNr;
  }
}
