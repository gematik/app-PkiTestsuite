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
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_ENDPOINT;

import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

  @GetMapping(value = TSL_XML_ENDPOINT, produces = MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML)
  public ResponseEntity<byte[]> getTslXml(
      @RequestParam(name = TSL_SEQNR_PARAM_ENDPOINT) final int activeTslSeqNr) {
    final ResponseEntity<byte[]> responseEntity = getResponseEntityWithTsl();
    addHistoryEntryIfResponseOk(activeTslSeqNr, responseEntity);
    return responseEntity;
  }

  @GetMapping(value = TSL_HASH_ENDPOINT)
  public ResponseEntity<String> getTslHash() {
    return getResponseEntityWithHash();
  }

  @GetMapping(value = TSL_XML_BACKUP_ENDPOINT, produces = MEDIA_TYPE_APPLICATION_VND_ETSI_TSL_XML)
  public ResponseEntity<byte[]> getTslXmlBackup() {
    return getResponseEntityWithTsl();
  }

  @GetMapping(value = TSL_HASH_BACKUP_ENDPOINT)
  public ResponseEntity<String> getTslHashBackup() {
    return getResponseEntityWithHash();
  }

  private ResponseEntity<byte[]> getResponseEntityWithTsl() {
    final byte[] tsl = getTsl();
    if (tsl.length == 0) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    } else {
      return ResponseEntity.ok(tsl);
    }
  }

  private ResponseEntity<String> getResponseEntityWithHash() {
    final byte[] tsl = getTsl();
    if (tsl.length == 0) {
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    } else {
      return ResponseEntity.ok(calculateSha256Hex(tsl));
    }
  }

  private byte[] getTsl() {

    if (tslConfigHolder.getTslProviderConfigDto() == null) {
      return new byte[0];
    }

    return Objects.requireNonNull(
            tslConfigHolder.getTslProviderConfigDto(),
            "TslProviderConfig is not initialized. Please configure via /config.")
        .getTslBytes();
  }

  private void addHistoryEntryIfResponseOk(
      final int sequenceNr, final ResponseEntity<byte[]> responseEntity) {
    if (responseEntity.getStatusCode() == HttpStatus.OK) {
      tslRequestHistory.add(new TslRequestHistoryEntryDto(sequenceNr, TSL_XML_ENDPOINT));
    }
  }
}
