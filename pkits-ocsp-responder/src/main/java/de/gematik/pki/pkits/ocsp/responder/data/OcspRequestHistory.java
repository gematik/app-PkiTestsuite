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

package de.gematik.pki.pkits.ocsp.responder.data;

import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.BiPredicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class OcspRequestHistory {

  private final List<OcspRequestHistoryEntryDto> history =
      Collections.synchronizedList(new ArrayList<>());

  private static final BiPredicate<OcspRequestHistoryEntryDto, Integer> predicateTslSeqNr =
      (historyEntry, tslSeqNr) ->
          (tslSeqNr == null)
              || (tslSeqNr == OcspResponderManager.IGNORE_SEQUENCE_NUMBER)
              || (historyEntry.getTslSeqNr() == tslSeqNr);

  private static final BiPredicate<OcspRequestHistoryEntryDto, BigInteger> predicateCertSerialNr =
      (historyEntry, certSerialNr) ->
          (certSerialNr == null)
              || certSerialNr.equals(OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER)
              || historyEntry.getCertSerialNr().equals(certSerialNr);

  public void add(final OcspRequestHistoryEntryDto newItem) {
    log.info("Add new entry in OCSP responder history: {}", newItem);
    history.add(newItem);
  }

  /**
   * @param tslSeqNr The requested TSL sequence number
   * @param certSerialNr The requested certificate serial number
   * @return A List with all OCSP-Requests for requested certificate serial number
   */
  public List<OcspRequestHistoryEntryDto> getExcerpt(
      final Integer tslSeqNr, final BigInteger certSerialNr) {

    return history.stream()
        .filter(
            historyEntry ->
                predicateTslSeqNr.test(historyEntry, tslSeqNr)
                    && predicateCertSerialNr.test(historyEntry, certSerialNr))
        .toList();
  }

  /**
   * @param tslSeqNr The requested TSL sequence number
   * @param certSerialNr The requested certificate serial number
   */
  public void deleteEntries(final Integer tslSeqNr, final BigInteger certSerialNr) {
    history.removeIf(
        historyEntry ->
            predicateTslSeqNr.test(historyEntry, tslSeqNr)
                && predicateCertSerialNr.test(historyEntry, certSerialNr));
  }

  public void deleteAll() {
    history.clear();
  }

  public int size() {
    return history.size();
  }
}
