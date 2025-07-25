/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.common;

import static org.awaitility.Awaitility.await;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.lang.StackWalker.StackFrame;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.awaitility.core.ConditionTimeoutException;
import org.junit.jupiter.params.provider.Arguments;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkitsTestSuiteUtils {

  public static long waitForEvent(
      final String name, final long timeoutSecs, final Callable<Boolean> eventChecker) {
    final int POLL_INTERVAL_MILLIS = 250;
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
    final ZonedDateTime timeStart = GemLibPkiUtils.now();
    try {
      await()
          .atMost(Duration.ofSeconds(timeoutSecs))
          .pollInterval(Duration.ofMillis(pollIntervalMillis))
          .until(eventChecker);
    } catch (final ConditionTimeoutException e) {
      final String message =
          "Timeout for event \"%s\"%n%s:%s%n:: %s%n"
              .formatted(name, e.getClass().getCanonicalName(), e.getMessage(), getCallerTrace());
      log.error(message);
      throw new TestSuiteException(message, e);
    }
    final ZonedDateTime timeEnd = GemLibPkiUtils.now();
    final long waitingTime = ChronoUnit.SECONDS.between(timeStart, timeEnd);
    log.info("Event \"{}\" occurred after: {} seconds.:: {}", name, waitingTime, getCallerTrace());
    return waitingTime;
  }

  public static Path buildAbsolutePath(@NonNull Path path) {

    if (!path.isAbsolute()) {
      path = Path.of(System.getProperty("user.dir"), path.toString());
    }
    return path;
  }

  public static Path buildAbsolutePathForDir(@NonNull Path path) {
    path = buildAbsolutePath(path);

    if (Files.isDirectory(path)) {
      return path;
    } else {
      throw new TestSuiteException("Path: " + path + " is not valid");
    }
  }

  public static String getShortenedStackTrace(final Throwable throwable) {
    String stackTrace = ExceptionUtils.getStackTrace(throwable);
    stackTrace =
        RegExUtils.replaceAll(
            stackTrace, "\tat (org.junit|java.base/).*", "\tat <org.junit or java.base>...");

    stackTrace =
        RegExUtils.replaceAll(
            stackTrace,
            "(\tat <org.junit or java.base>...\r?\n)+",
            "\tat <org.junit or java.base>...X times \n");
    return stackTrace;
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

      final String currentClassName = ClassUtils.getShortClassName(frame.getClassName());
      final String className;
      if (!currentClassName.equals(previousClassName)) {
        className = currentClassName + ".";
      } else {
        className = "";
      }

      previousClassName = currentClassName;

      final String part =
          "%s%s:%d".formatted(className, frame.getMethodName(), frame.getLineNumber());

      parts.add(part);
    }

    return String.join(" --> ", parts);
  }

  public static Stream<Arguments> provideForMissingOcspSigner() {
    return Stream.of(
        Arguments.of(PkitsTestDataConstants.OCSP_SIGNER_NOT_IN_TSL),
        Arguments.of(PkitsTestDataConstants.OCSP_SIGNER_DIFFERENT_KEY));
  }

  public static Stream<Arguments> provideOcspResponseVariousStatusAndResponseBytes() {
    final List<Arguments> argumentsList = new ArrayList<>();
    for (final OCSPRespStatus ocspRespStatus :
        List.of(
            OCSPRespStatus.INTERNAL_ERROR,
            OCSPRespStatus.MALFORMED_REQUEST,
            OCSPRespStatus.SIG_REQUIRED,
            OCSPRespStatus.TRY_LATER,
            OCSPRespStatus.UNAUTHORIZED)) {
      for (final boolean withResponseBytes : List.of(true, false)) {
        argumentsList.add(Arguments.of(ocspRespStatus, withResponseBytes));
      }
    }
    return argumentsList.stream();
  }
}
