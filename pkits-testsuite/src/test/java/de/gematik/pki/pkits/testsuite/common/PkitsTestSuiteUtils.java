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

package de.gematik.pki.pkits.testsuite.common;

import static org.awaitility.Awaitility.await;

import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.Callable;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.awaitility.core.ConditionTimeoutException;

@Slf4j
public class PkitsTestSuiteUtils {

  public static void waitForEvent(
      final String name, final long timeoutSecs, final Callable<Boolean> eventChecker) {
    final int POLL_INTERVAL_SECS = 1;
    waitForEvent(name, timeoutSecs, POLL_INTERVAL_SECS, eventChecker);
  }

  public static void waitForEvent(
      final String name,
      final long timeoutSecs,
      final long pollIntervalSecs,
      final Callable<Boolean> eventChecker) {
    log.debug(
        "Waiting for event \"{}\" with timeout: {} seconds, poll interval: {} seconds",
        name,
        timeoutSecs,
        pollIntervalSecs);
    final ZonedDateTime zdtStart = ZonedDateTime.now();
    try {
      await()
          .atMost(Duration.ofSeconds(timeoutSecs))
          .pollInterval(Duration.ofSeconds(pollIntervalSecs))
          .until(eventChecker);
    } catch (final ConditionTimeoutException e) {
      final String message = "Timeout for event \"%s\"".formatted(name);
      log.error(message, e);
      throw new TestSuiteException(message, e);
    }
    final ZonedDateTime zdtEnd = ZonedDateTime.now();
    log.info(
        "Event \"{}\" occurred after: {} seconds",
        name,
        ChronoUnit.SECONDS.between(zdtStart, zdtEnd));
  }

  public static Path buildAbsolutePath(@NonNull final String aPath) {
    Path p = Paths.get(aPath);
    if (!p.isAbsolute()) {
      p = Paths.get(System.getProperty("user.dir") + "/" + aPath);
    }
    if (Files.isDirectory(p)) {
      return p;
    } else {
      throw new TestSuiteException("Path: " + aPath + " is not valid");
    }
  }
}
