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
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OcspHistory {

  @Getter
  @AllArgsConstructor
  public enum OcspRequestExpectationBehaviour {
    OCSP_REQUEST_EXPECT(1),
    OCSP_REQUEST_DO_NOT_EXPECT(0),
    OCSP_REQUEST_IGNORE(-1);

    private final int expectedRequestAmount;
  }

  /**
   * Check if certSerialNr matches all entries and amount
   *
   * @param certSerialNr certificate serial number
   */
  public static void check(
      final String ocspRespUri,
      final BigInteger certSerialNr,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {

    final List<OcspRequestHistoryEntryDto> history =
        OcspResponderManager.getOcspHistoryPart(ocspRespUri, certSerialNr);

    if (ocspRequestExpectationBehaviour == OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE) {
      return;
    }

    assertThat(history)
        .as(
            "Expected %d OCSP requests for certificate %s, but received %d"
                .formatted(
                    ocspRequestExpectationBehaviour.getExpectedRequestAmount(),
                    certSerialNr,
                    history.size()))
        .hasSize(ocspRequestExpectationBehaviour.getExpectedRequestAmount());

    for (int i = 0; i < ocspRequestExpectationBehaviour.getExpectedRequestAmount(); i++) {
      // Double check. A fail indicates an implementation error in OcspResponder.
      assertThat(history.get(i).getCertSerialNr())
          .as("OCSP request history error. Expected CertSerialNr does not match.")
          .isEqualTo(certSerialNr);
    }
  }
}
