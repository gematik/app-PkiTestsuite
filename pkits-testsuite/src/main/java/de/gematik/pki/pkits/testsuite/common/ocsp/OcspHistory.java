/*
 * Copyright 2023 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslSequenceNr;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.awaitility.core.ConditionTimeoutException;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspHistory {

  static final OcspRequestHistoryContainer OCSP_REQUEST_HISTORY_CONTAINER =
      new OcspRequestHistoryContainer();

  /**
   * Check if certSerialNr matches all entries and amount
   *
   * @param certSerialNr certificate serial number
   */
  public static Optional<Integer> check(
      final String ocspRespUri,
      final BigInteger certSerialNr,
      final TslSequenceNr tslSequenceNr,
      final int ocspProcessingTimeSeconds,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {

    try {
      OCSP_REQUEST_HISTORY_CONTAINER.reset();
      final long ocsRequestWaitingTimeSeconds =
          PkitsTestSuiteUtils.waitForEvent(
              "OcspRequestHistoryHasEntry for tslSeqNr %s and cert %s"
                  .formatted(tslSequenceNr, certSerialNr),
              ocspProcessingTimeSeconds,
              OCSP_REQUEST_HISTORY_CONTAINER.ocspRequestHistoryHasEntryForCert(
                  ocspRespUri, TslRequestHistory.IGNORE_SEQUENCE_NUMBER, certSerialNr));
      log.info(
          "OCSP Request for certificate received after {} seconds.", ocsRequestWaitingTimeSeconds);
    } catch (final TestSuiteException e) {
      if (!(e.getCause() instanceof ConditionTimeoutException)) {
        throw e;
      }
      if (ocspRequestExpectationBehaviour == OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT) {
        throw e;
      }
      return Optional.empty();
    } finally {
      TestEnvironment.clearOcspResponderConfig(ocspRespUri);
    }

    final Optional<Integer> rxMaxTslSeqNr =
        getCurrentTslSeqNr(OCSP_REQUEST_HISTORY_CONTAINER.getHistoryEntries());

    final List<OcspRequestHistoryEntryDto> historyEntries =
        OCSP_REQUEST_HISTORY_CONTAINER.getHistoryEntries();
    final String historyStr =
        historyEntries.stream()
            .map(OcspRequestHistoryEntryDto::toString)
            .collect(Collectors.joining("\n"));

    log.info("expectedTslSeqNr: {}", tslSequenceNr.getExpectedNrInTestObject());
    log.info("ocsp-history: {}", historyStr);

    if (ocspRequestExpectationBehaviour != OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE) {
      assertThat(historyEntries)
          .as(
              "Expected %d OCSP requests for certificate %s, but received %d"
                  .formatted(
                      ocspRequestExpectationBehaviour.getExpectedRequestAmount(),
                      certSerialNr,
                      historyEntries.size()))
          .hasSize(ocspRequestExpectationBehaviour.getExpectedRequestAmount());
    }

    // TODO clarify what if there are multiple entries in history and
    //      ocspRequestExpectationBehaviour.getExpectedRequestAmount() > 1
    //      we change OcspRequestExpectationBehaviour when necessary
    for (int i = 0; i < ocspRequestExpectationBehaviour.getExpectedRequestAmount(); i++) {
      final OcspRequestHistoryEntryDto historyEntry = historyEntries.get(i);
      log.info(
          "compare tslSeqNr - expected: {}, from history {}",
          tslSequenceNr.getExpectedNrInTestObject(),
          historyEntry.getTslSeqNr());
      // Double check. A fail indicates an implementation error in OcspResponder.
      assertThat(historyEntry.getCertSerialNr())
          .as("OCSP request history error. Expected CertSerialNr does not match.")
          .isEqualTo(certSerialNr);
      assertThat(historyEntry.getTslSeqNr())
          .as("OCSP request history error. Expected tslSeqNr does not match.")
          .isEqualTo(tslSequenceNr.getExpectedNrInTestObject());
    }
    return rxMaxTslSeqNr;
  }

  /**
   * Find maximum Tsl sequence number in requested ocsp history and set this number as current in
   * test object.
   *
   * @param history to get the seq number from
   * @return optional largest tslSeqNr for the history
   */
  public static Optional<Integer> getCurrentTslSeqNr(
      final List<OcspRequestHistoryEntryDto> history) {
    return history.stream().map(OcspRequestHistoryEntryDto::getTslSeqNr).max(Integer::compareTo);
  }
}
