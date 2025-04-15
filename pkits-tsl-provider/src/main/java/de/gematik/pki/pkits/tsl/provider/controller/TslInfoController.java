/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.tsl.provider.controller;

import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import io.swagger.v3.oas.annotations.Operation;
import java.util.Collections;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class TslInfoController {
  private final TslRequestHistory tslRequestHistory;

  /**
   * @param tslInfoRequest TslInfoRequestDto
   * @return An excerpt of the history of requests
   */
  @Operation(summary = "Get history entries according to the provided info request.")
  @PostMapping(value = PkitsConstants.TSL_WEBSERVER_INFO_ENDPOINT)
  public List<TslRequestHistoryEntryDto> info(final @RequestBody TslInfoRequestDto tslInfoRequest) {

    log.debug("InfoRequest for tslSeqNr {} received.", tslInfoRequest.getTslSeqNr());
    final List<TslRequestHistoryEntryDto> list =
        tslRequestHistory.getExcerpt(tslInfoRequest.getTslSeqNr());

    log.debug("Found history with {} entries.", list.size());
    deleteHistoryOnDemand(tslInfoRequest);

    return Collections.unmodifiableList(list);
  }

  private void deleteHistoryOnDemand(final TslInfoRequestDto tslInfoRequestDto) {
    switch (tslInfoRequestDto.getHistoryDeleteOption()) {
      case DELETE_FULL_HISTORY -> {
        tslRequestHistory.deleteAll();
        log.debug("TSLProvider history: cleared");
      }
      case DELETE_SEQNR_ENTRY -> {
        tslRequestHistory.deleteEntries(tslInfoRequestDto.getTslSeqNr());
        log.debug("TSLProvider history: cleared tslSeqNr {}", tslInfoRequestDto.getTslSeqNr());
      }
        // HistoryDeleteOption.DELETE_NOTHING
      default -> log.debug("deleteHistoryOnDemand called without delete option.");
    }
  }
}
