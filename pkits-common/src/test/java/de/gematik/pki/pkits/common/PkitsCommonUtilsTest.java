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

package de.gematik.pki.pkits.common;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.calculateSha256Hex;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;

class PkitsCommonUtilsTest {

  @Test
  void verifyCalculateSha256HexValid() {
    assertThat(calculateSha256Hex("Das ist ein Teststring!".getBytes()))
        .isEqualTo("66057df8c7aa189868be072ba859ed629f627b341afc5611982c316376011869");
  }

  @Test
  void verifyWaitSeconds() {
    final long secondsToWait = 3;
    final ZonedDateTime zdtNow = ZonedDateTime.now();
    PkitsCommonUtils.waitSeconds(secondsToWait);
    final ZonedDateTime zdtLater = ZonedDateTime.now();
    AssertionsForClassTypes.assertThat(zdtNow.plusSeconds(secondsToWait).isBefore(zdtLater))
        .as("Before wait:\n" + zdtNow + ", after wait:\n" + zdtLater)
        .isTrue();
  }

  @Test
  void verifyWaitMilliSeconds() {
    final long milliSecondsToWait = 300;
    final ZonedDateTime zdtNow = ZonedDateTime.now();
    PkitsCommonUtils.waitMilliseconds(milliSecondsToWait);
    final ZonedDateTime zdtLater = ZonedDateTime.now();
    AssertionsForClassTypes.assertThat(
            zdtNow.plus(milliSecondsToWait, ChronoUnit.MILLIS).isBefore(zdtLater))
        .as("Before wait:\n" + zdtNow + ", after wait:\n" + zdtLater)
        .isTrue();
  }
}
