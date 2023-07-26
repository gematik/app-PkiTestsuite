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

package de.gematik.pki.pkits.testsuite.common.ocsp;

import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.Callable;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OcspRequestHistoryContainer {

  @Getter private List<OcspRequestHistoryEntryDto> historyEntries = List.of();

  public void reset() {
    historyEntries = List.of();
  }

  public Callable<Boolean> ocspRequestHistoryHasEntryForCert(
      final String ocspRespUri, final int tslSeqNr, final BigInteger certSerial) {
    log.debug("Polling TSL download request history");
    return () -> {
      historyEntries = OcspResponderManager.getOcspHistoryPart(ocspRespUri, tslSeqNr, certSerial);
      return !historyEntries.isEmpty();
    };
  }
}
