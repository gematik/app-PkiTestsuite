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

package de.gematik.pki.pkits.testsuite.common.ocsp;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import java.math.BigInteger;
import java.util.List;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OcspHistory {

  /**
   * Check if certSerialNr matches all entries and amount
   *
   * @param certSerialNr certificate serial number
   * @param expectedRequestAmount expected amount of history entries
   */
  public static void check(
      final String ocspRespUri, final BigInteger certSerialNr, final int expectedRequestAmount) {
    final List<OcspRequestHistoryEntryDto> history =
        OcspResponderManager.getOcspHistoryPart(ocspRespUri, certSerialNr);
    if (history.size() != expectedRequestAmount) {
      log.error(
          "Expected {} OCSP requests for certificate {}, but received {}",
          expectedRequestAmount,
          certSerialNr,
          history.size());
    }
    assertThat(history)
        .as(
            "Expected "
                + expectedRequestAmount
                + " OCSP requests for certificate "
                + certSerialNr
                + ", but received "
                + history.size())
        .hasSize(expectedRequestAmount);
    for (int i = 0; i < expectedRequestAmount; i++) {
      // Double check. A fail indicates an implementation error in OcspResponder.
      assertThat(history.get(i).getCertSerialNr())
          .as("OCSP request history error. Expected CertSerialNr does not match.")
          .isEqualTo(certSerialNr);
    }
  }
}
