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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.calculateSha256Hex;
import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;

import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
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

  @GetMapping(value = TSL_XML_PRIMARY_ENDPOINT, produces = MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML)
  public ResponseEntity<byte[]> getTslXmlPrimary(
      final HttpServletRequest request,
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {

    log.info("Starting tsl xml endpoint at {}", TSL_XML_PRIMARY_ENDPOINT);
    addHistoryEntry(activeTslSeqNr, TSL_XML_PRIMARY_ENDPOINT, request);
    return getResponseEntityWithTsl(true);
  }

  @GetMapping(value = TSL_HASH_PRIMARY_ENDPOINT)
  public ResponseEntity<String> getTslHashPrimary(
      final HttpServletRequest request,
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {
    log.info("Starting tsl hash endpoint at {}", TSL_HASH_PRIMARY_ENDPOINT);
    addHistoryEntry(activeTslSeqNr, TSL_HASH_PRIMARY_ENDPOINT, request);
    return getResponseEntityWithHash();
  }

  @GetMapping(value = TSL_XML_BACKUP_ENDPOINT, produces = MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML)
  public ResponseEntity<byte[]> getTslXmlBackup(
      final HttpServletRequest request,
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {
    log.info("Starting tsl backup xml endpoint at {}", TSL_XML_BACKUP_ENDPOINT);
    addHistoryEntry(activeTslSeqNr, TSL_XML_BACKUP_ENDPOINT, request);
    return getResponseEntityWithTsl(false);
  }

  @GetMapping(value = TSL_HASH_BACKUP_ENDPOINT)
  public ResponseEntity<String> getTslHashBackup(
      final HttpServletRequest request,
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {

    log.info("Starting tsl backup hash endpoint at {}", TSL_HASH_BACKUP_ENDPOINT);
    addHistoryEntry(activeTslSeqNr, TSL_HASH_BACKUP_ENDPOINT, request);
    return getResponseEntityWithHash();
  }

  private ResponseEntity<byte[]> getResponseEntityWithTsl(final boolean isPrimaryEndpoint) {

    if (!tslConfigHolder.isConfigured()) {
      return ResponseEntity.internalServerError()
          .body(NOT_CONFIGURED.getBytes(StandardCharsets.UTF_8));
    }

    final TslProviderEndpointsConfig tslProviderEndpointsConfig =
        tslConfigHolder.getTslProviderConfigDto().getTslProviderEndpointsConfig();

    final int statusCode;
    if (isPrimaryEndpoint) {
      statusCode = tslProviderEndpointsConfig.getPrimaryStatusCode();
    } else {
      statusCode = tslProviderEndpointsConfig.getBackupStatusCode();
    }

    if (statusCode == HttpStatus.NOT_FOUND.value()) {
      log.info("statusCode=404 -> response with http status {}", HttpStatus.NOT_FOUND);
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    final byte[] tsl = getTsl();

    if (tsl.length == 0) {
      log.info("tsl.length == 0 -> response with status code {}", HttpStatus.INTERNAL_SERVER_ERROR);
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
      final int activeTslSeqNr, final String endpoint, final HttpServletRequest request) {
    final String protocol = request.getProtocol();
    tslRequestHistory.add(activeTslSeqNr, endpoint, isGzipCompressed(request), protocol);
  }
}
