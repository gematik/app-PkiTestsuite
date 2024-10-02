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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getFirstSingleResp;
import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponderException;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.CertificateDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.math.BigInteger;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class OcspRequestController {

  private final OcspRequestHistory ocspRequestHistory;
  private final OcspResponseConfigHolder ocspResponseConfigHolder;

  @Operation(
      summary =
          "Generates OCSP response for the provided sequence number and according to the current"
              + " configuration of the OCSP Responder.",
      description =
          "Example with curl: ```curl -v --request 'POST'  'http://localhost:8083/ocsp/1000000'  -H"
              + " 'accept: application/ocsp-response'  -H 'Content-Type: application/ocsp-request'"
              + " --data-binary \"@ocspRequestBytes.bin\"```",
      parameters = {
        @Parameter(in = ParameterIn.PATH, name = "seqNr", description = "sequence number from TSL")
      })
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Generate OCSP response.",
            content = {@Content(mediaType = OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_REQUEST)}),
        @ApiResponse(
            responseCode = "500",
            description = "OCSP Responder not configured",
            content = @Content)
      })
  @PostMapping(
      value = OCSP_SSP_ENDPOINT + "/{seqNr}",
      consumes = OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_REQUEST,
      produces = OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
  public ResponseEntity<Object> ocspService(
      @PathVariable("seqNr") final int tslSeqNr,
      final HttpServletRequest request,
      final @io.swagger.v3.oas.annotations.parameters.RequestBody(
              description = "Binary encoding of the instance of OCSP Request.",
              required = true) @RequestBody byte[] ocspRequestBytes) {

    if (!ocspResponseConfigHolder.isConfigured()) {
      return ResponseEntity.internalServerError().body(NOT_CONFIGURED);
    }

    final OCSPReq ocspReq = createOcspReqFromServletRequest(ocspRequestBytes);
    final BigInteger certSerialNr = getCertSerialNrFromRequest(ocspReq);
    Optional<CertificateDto> certificateDto =
        ocspResponseConfigHolder.getCertificateFromSerialNr(certSerialNr);
    if (certificateDto.isEmpty()) {
      log.error("CertSerialNr {} is not configured.", certSerialNr);
      throw new OcspResponderException("CertSerialNr is not configured");
    }

    final byte[] ocspReqBytes;
    try {
      ocspReqBytes = ocspReq.getEncoded();
    } catch (final IOException e) {
      throw new OcspResponderException("Cannot serialize ocspReq", e);
    }

    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(
            tslSeqNr, certSerialNr, ZonedDateTime.now().toString(), ocspReqBytes));
    log.info(
        "Build OCSP Response for tslSeqNr {} and certSerialNr {} and send to {}:{}",
        tslSeqNr,
        certSerialNr,
        request.getRemoteHost(),
        request.getRemotePort());

    final int delayMilliseconds = certificateDto.get().getDelayMilliseconds();

    if (delayMilliseconds < 0) {
      throw new PkiCommonException("delayMilliseconds is < 0");
    }

    final byte[] ocspResponseBytes = buildOcspResponseBytes(ocspReq, certificateDto.get());

    if (delayMilliseconds > 0) {
      log.info("Delay sending OCSP Response for {} milliseconds", delayMilliseconds);
      PkitsCommonUtils.waitMilliseconds(delayMilliseconds);
    }
    log.info("Sending OCSP response.");
    return new ResponseEntity<>(ocspResponseBytes, HttpStatus.OK);
  }

  private byte[] buildOcspResponseBytes(final OCSPReq ocspReq, final CertificateDto certificate) {
    final ZonedDateTime now = GemLibPkiUtils.now();

    ZonedDateTime nextUpdate = null;
    if (certificate.getNextUpdateDeltaMilliseconds() != null) {
      nextUpdate = now.plus(certificate.getNextUpdateDeltaMilliseconds(), ChronoUnit.MILLIS);
    }

    final OcspResponseGenerator ocspResponseGenerator =
        OcspResponseGenerator.builder()
            .signer(certificate.getSigner())
            .withCertHash(certificate.isWithCertHash())
            .validCertHash(certificate.isValidCertHash())
            .validSignature(certificate.isValidSignature())
            .certificateIdGeneration(certificate.getCertificateIdGeneration())
            .responderIdType(certificate.getResponderIdType())
            .respStatus(certificate.getRespStatus())
            .withResponseBytes(certificate.isWithResponseBytes())
            .thisUpdate(now.plus(certificate.getThisUpdateDeltaMilliseconds(), ChronoUnit.MILLIS))
            .producedAt(now.plus(certificate.getProducedAtDeltaMilliseconds(), ChronoUnit.MILLIS))
            .nextUpdate(nextUpdate)
            .withNullParameterHashAlgoOfCertId(certificate.isWithNullParameterHashAlgoOfCertId())
            .responseAlgoBehavior(certificate.getResponseAlgoBehavior())
            .build();
    try {

      final OCSPResp ocspResponse =
          ocspResponseGenerator.generate(
              ocspReq,
              certificate.getEeCert(),
              certificate.getIssuerCert(),
              certificate.getOcspCertificateStatus());

      final Extension certHashExtension =
          getFirstSingleResp(ocspResponse).getExtension(id_isismtt_at_certHash);

      byte[] certHash = null;
      if (certHashExtension != null) {
        certHash = CertHash.getInstance(certHashExtension.getParsedValue()).getCertificateHash();
      }

      log.debug(
          "Building OcspResponse done. CertHash: {}.",
          certHash != null ? Hex.toHexString(certHash) : "not included");

      return ocspResponse.getEncoded();
    } catch (final IOException e) {
      throw new OcspResponderException("Could not create OcspResponse.", e);
    }
  }

  private OCSPReq createOcspReqFromServletRequest(final byte[] ocspRequestBytes) {

    try {
      return new OCSPReq(ocspRequestBytes);
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
