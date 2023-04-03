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

package de.gematik.pki.pkits.testsuite.common;

import static org.awaitility.Awaitility.await;

import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.lang.StackWalker.StackFrame;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ClassUtils;
import org.awaitility.core.ConditionTimeoutException;

@Slf4j
public class PkitsTestSuiteUtils {

  public static long waitForEvent(
      final String name, final long timeoutSecs, final Callable<Boolean> eventChecker) {
    final int POLL_INTERVAL_MILLIS = 500;
    return waitForEventMillis(name, timeoutSecs, POLL_INTERVAL_MILLIS, eventChecker);
  }

  public static long waitForEventMillis(
      final String name,
      final long timeoutSecs,
      final long pollIntervalMillis,
      final Callable<Boolean> eventChecker) {
    log.debug(
        "Waiting for event \"{}\" with timeout: {} milliseconds, poll interval: {} seconds",
        name,
        timeoutSecs,
        pollIntervalMillis);
    final ZonedDateTime zdtStart = ZonedDateTime.now();
    try {
      await()
          .atMost(Duration.ofSeconds(timeoutSecs))
          .pollInterval(Duration.ofMillis(pollIntervalMillis))
          .until(eventChecker);
    } catch (final ConditionTimeoutException e) {
      final String message = "Timeout for event \"%s\":: %s".formatted(name, getCallerTrace());
      log.error(message, e);
      throw new TestSuiteException(message, e);
    }
    final ZonedDateTime zdtEnd = ZonedDateTime.now();
    final long waitingTime = ChronoUnit.SECONDS.between(zdtStart, zdtEnd);
    log.info("Event \"{}\" occurred after: {} seconds.:: {}", name, waitingTime, getCallerTrace());
    return waitingTime;
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

  public static String getCallerTrace() {
    final String testsPackageName = "de.gematik.pki.pkits.testsuite";
    final Predicate<StackFrame> takePredicate =
        stackFrame -> {
          final String packageName = ClassUtils.getPackageName(stackFrame.getClassName());
          return packageName.startsWith(testsPackageName);
        };

    // skip getCallerTrace itself
    final List<StackFrame> framesOrig =
        StackWalker.getInstance().walk(stream -> stream.takeWhile(takePredicate).skip(1).toList());

    final List<StackFrame> frames = new ArrayList<>(framesOrig);

    Collections.reverse(frames);

    final List<String> parts = new ArrayList<>();

    String previousClassName = "";
    for (final StackFrame frame : frames) {

      String currentClassName = ClassUtils.getShortClassName(frame.getClassName());
      final String className;
      if (!currentClassName.equals(previousClassName)) {
        className = currentClassName + ".";
      } else {
        className = "";
      }

      previousClassName = currentClassName;

      String part = "%s%s:%d".formatted(className, frame.getMethodName(), frame.getLineNumber());

      parts.add(part);
    }

    return String.join(" --> ", parts);
  }
}
