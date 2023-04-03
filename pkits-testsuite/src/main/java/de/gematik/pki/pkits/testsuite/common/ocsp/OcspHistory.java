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

package de.gematik.pki.pkits.testsuite.common.ocsp;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.testsuite.common.tsl.TslSequenceNr;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
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
      final TslSequenceNr tslSequenceNr,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {

    final List<OcspRequestHistoryEntryDto> history =
        OcspResponderManager.getOcspHistoryPart(
            ocspRespUri, TslRequestHistory.IGNORE_SEQUENCE_NUMBER, certSerialNr);

    setCurrentTslSeqNr(tslSequenceNr, history);

    final String historyStr =
        history.stream()
            .map(OcspRequestHistoryEntryDto::toString)
            .collect(Collectors.joining("\n"));

    log.info("expectedSeqNr: {}", tslSequenceNr.getExpectedNrInTestObject());
    log.info("ocsp-history: {}", historyStr);
    if (ocspRequestExpectationBehaviour != OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE) {
      assertThat(history)
          .as(
              "Expected %d OCSP requests for certificate %s, but received %d"
                  .formatted(
                      ocspRequestExpectationBehaviour.getExpectedRequestAmount(),
                      certSerialNr,
                      history.size()))
          .hasSize(ocspRequestExpectationBehaviour.getExpectedRequestAmount());
    }

    // TODO clarify what if there are multiple entries in history and
    //      ocspRequestExpectationBehaviour.getExpectedRequestAmount() > 1
    //      we change OcspRequestExpectationBehaviour when necessary
    for (int i = 0; i < ocspRequestExpectationBehaviour.getExpectedRequestAmount(); i++) {
      log.info(
          "compare seqNr - expected: {}, from history {}",
          tslSequenceNr.getExpectedNrInTestObject(),
          history.get(i).getTslSeqNr());
      // Double check. A fail indicates an implementation error in OcspResponder.
      assertThat(history.get(i).getCertSerialNr())
          .as("OCSP request history error. Expected CertSerialNr does not match.")
          .isEqualTo(certSerialNr);
      assertThat(history.get(i).getTslSeqNr())
          .as("OCSP request history error. Expected seqNr does not match.")
          .isEqualTo(tslSequenceNr.getExpectedNrInTestObject());
    }
  }

  /**
   * Find maximum Tsl sequence number in requested ocsp history and set this number as current in
   * test object.
   *
   * @param tslSequenceNr
   * @param history
   */
  private static void setCurrentTslSeqNr(
      final TslSequenceNr tslSequenceNr, final List<OcspRequestHistoryEntryDto> history) {
    final Optional<Integer> rxMaxTslSeqNr =
        history.stream().map(OcspRequestHistoryEntryDto::getTslSeqNr).max(Integer::compareTo);
    rxMaxTslSeqNr.ifPresent(tslSequenceNr::saveCurrentTestObjectSeqNr);
  }
}
