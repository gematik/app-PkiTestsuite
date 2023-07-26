/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.tsl.provider.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class TslRequestHistory {

  public static final int IGNORE_SEQUENCE_NUMBER = -1;

  private final List<TslRequestHistoryEntryDto> history =
      Collections.synchronizedList(new ArrayList<>());

  public void add(final TslRequestHistoryEntryDto newItem) {
    log.debug("Add new entry with tslSeqNr: {} - {}", newItem.getTslSeqNr(), newItem);
    history.add(newItem);
  }

  public void add(
      final int tslSeqNr,
      final String endpoint,
      final boolean isGzipCompressed,
      final String protocol) {

    final TslRequestHistoryEntryDto newItem =
        new TslRequestHistoryEntryDto(tslSeqNr, endpoint, isGzipCompressed, protocol);

    add(newItem);
  }

  public List<TslRequestHistoryEntryDto> getExcerpt(final int tslSeqNr) {

    final boolean requestedFullHistory = (tslSeqNr == IGNORE_SEQUENCE_NUMBER);

    return history.stream()
        .filter(historyEntry -> requestedFullHistory || (historyEntry.getTslSeqNr() == tslSeqNr))
        .toList();
  }

  public void deleteEntries(final int tslSeqNr) {
    history.removeIf(historyEntry -> historyEntry.getTslSeqNr() == tslSeqNr);
  }

  public void deleteAll() {
    history.clear();
  }

  public int size() {
    return history.size();
  }
}
