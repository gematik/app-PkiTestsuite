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

  private final List<TslRequestHistoryEntryDto> history = new ArrayList<>();

  public void add(final TslRequestHistoryEntryDto newItem) {
    log.info("Add new entry with sequence number: {}", newItem.getSequenceNr());
    history.add(newItem);
  }

  public List<TslRequestHistoryEntryDto> getExcerpt(final int sequenceNr) {
    final List<TslRequestHistoryEntryDto> excerpt = new ArrayList<>();
    final boolean FULL_HISTORY_IS_REQUESTED = (sequenceNr == IGNORE_SEQUENCE_NUMBER);
    for (final TslRequestHistoryEntryDto entry : history) {
      if (FULL_HISTORY_IS_REQUESTED || (entry.getSequenceNr() == sequenceNr)) {
        excerpt.add(entry);
      }
    }
    return Collections.unmodifiableList(excerpt);
  }

  public void deleteEntries(final int sequenceNr) {
    history.removeIf(requestHistoryEntry -> requestHistoryEntry.getSequenceNr() == sequenceNr);
  }

  public void deleteAll() {
    history.clear();
  }
}
