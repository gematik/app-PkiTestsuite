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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.calculateSha256Hex;
import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_ENDPOINT;

import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class TslProviderController {

  public static final String MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML =
      "application/vnd.etsi.tsl+xml";
  private final TslConfigHolder tslConfigHolder;
  private final TslRequestHistory tslRequestHistory;

  private static boolean isGzipCompressed(final HttpServletRequest request) {
    final Iterator<String> headerValuesIter =
        request.getHeaders(HttpHeaders.ACCEPT_ENCODING).asIterator();

    final List<String> headerValues = new ArrayList<>();
    headerValuesIter.forEachRemaining(headerValues::add);

    return headerValues.stream().anyMatch(v -> v.contains("gzip"));
  }

  @GetMapping(value = TSL_XML_ENDPOINT, produces = MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML)
  public ResponseEntity<byte[]> getTslXmlPrimary(
      final HttpServletRequest request,
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {

    final String protocol = request.getProtocol();

    final ResponseEntity<byte[]> responseEntity = getResponseEntityWithTsl();
    addHistoryEntry(activeTslSeqNr, isGzipCompressed(request), protocol);
    return responseEntity;
  }

  @GetMapping(value = TSL_HASH_ENDPOINT)
  public ResponseEntity<String> getTslHashPrimary(
      final HttpServletRequest request,
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {
    addHistoryEntry(activeTslSeqNr, isGzipCompressed(request), request.getProtocol());
    return getResponseEntityWithHash();
  }

  @GetMapping(value = TSL_XML_BACKUP_ENDPOINT, produces = MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML)
  public ResponseEntity<byte[]> getTslXmlBackup(
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {
    return getResponseEntityWithTsl();
  }

  @GetMapping(value = TSL_HASH_BACKUP_ENDPOINT)
  public ResponseEntity<String> getTslHashBackup(
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {
    return getResponseEntityWithHash();
  }

  private ResponseEntity<byte[]> getResponseEntityWithTsl() {

    if (!tslConfigHolder.isConfigured()) {
      return ResponseEntity.internalServerError().body(NOT_CONFIGURED.getBytes());
    }

    final byte[] tsl = getTsl();

    if (tsl.length == 0) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    } else {
      return ResponseEntity.ok(tsl);
    }
  }

  private ResponseEntity<String> getResponseEntityWithHash() {

    if (!tslConfigHolder.isConfigured()) {
      return ResponseEntity.internalServerError().body(NOT_CONFIGURED);
    }

    final byte[] tsl = getTsl();

    if (tsl.length == 0) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    } else {
      return ResponseEntity.ok(calculateSha256Hex(tsl));
    }
  }

  private byte[] getTsl() {
    return tslConfigHolder.getTslProviderConfigDto().getTslBytes();
  }

  private void addHistoryEntry(
      final int sequenceNr, final boolean isGzipCompressed, final String protocol) {

    final TslRequestHistoryEntryDto entry =
        new TslRequestHistoryEntryDto(sequenceNr, TSL_XML_ENDPOINT, isGzipCompressed, protocol);
    tslRequestHistory.add(entry);
  }
}
