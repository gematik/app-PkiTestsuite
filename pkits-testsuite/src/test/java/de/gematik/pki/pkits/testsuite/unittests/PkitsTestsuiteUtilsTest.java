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

package de.gematik.pki.pkits.testsuite.unittests;

import static de.gematik.pki.pkits.testsuite.common.PkitsTestsuiteUtils.waitForEvent;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.pkits.testsuite.exceptions.TestsuiteException;
import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PkitsTestsuiteUtilsTest {

  static int eventCounter = 0;

  @BeforeEach
  void init() {
    eventCounter = 0;
  }

  @Test
  void awaitUntilEvent() {
    assertDoesNotThrow(
        () ->
            await()
                .atMost(3, TimeUnit.SECONDS)
                .pollInterval(Duration.ofMillis(1))
                .until(hitNumber(20)));
  }

  @Test
  void waitForEventSuccess() {
    assertDoesNotThrow(() -> waitForEvent("hit number", 16, hitNumber(13)));
  }

  @Test
  void waitForEventTimeout() {
    assertThatThrownBy(() -> waitForEvent("hit number", 2, hitNumber(13)))
        .isInstanceOf(TestsuiteException.class);
  }

  @Test
  void hitNumberTest() throws Exception {
    final int LOOP_COUNT = 20;
    for (int i = 0; i < LOOP_COUNT; i++) {
      final boolean ret = hitNumber(LOOP_COUNT).call();
      assertThat(ret).as("Callable is expected to return false.").isFalse();
    }
    final boolean ret = hitNumber(LOOP_COUNT).call();
    assertThat(ret).as("Callable is expected to return true.").isTrue();
  }

  private static Callable<Boolean> hitNumber(final int number) {
    return () -> {
      eventCounter++;
      return eventCounter > number;
    };
  }
}
