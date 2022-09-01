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

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_INFO_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class TslInfoController {

  private final TslRequestHistory tslRequestHistory;

  /**
   * @param request InfoRequest
   * @return An excerpt of the history of requests
   * @throws IOException in case of ServletInputStream problem
   */
  @PostMapping(value = WEBSERVER_INFO_ENDPOINT)
  public List<TslRequestHistoryEntryDto> info(final HttpServletRequest request) throws IOException {

    final TslInfoRequestDto tslInfoRequest =
        new ObjectMapper().readValue(request.getInputStream(), TslInfoRequestDto.class);

    log.info("InfoRequest for SequenceNr: {} received.", tslInfoRequest.getSequenceNr());
    final List<TslRequestHistoryEntryDto> list =
        tslRequestHistory.getExcerpt(tslInfoRequest.getSequenceNr());

    log.info("Found history with {} entries.", list.size());
    deleteHistoryOnDemand(tslInfoRequest);

    return Collections.unmodifiableList(list);
  }

  private void deleteHistoryOnDemand(final TslInfoRequestDto tslInfoRequestDto) {
    switch (tslInfoRequestDto.getHistoryDeleteOption()) {
      case DELETE_FULL_HISTORY -> tslRequestHistory.deleteAll();
      case DELETE_SEQNR_ENTRY -> tslRequestHistory.deleteEntries(tslInfoRequestDto.getSequenceNr());
      default -> log.debug("deleteHistoryOnDemand called without delete option.");
    }
  }
}
