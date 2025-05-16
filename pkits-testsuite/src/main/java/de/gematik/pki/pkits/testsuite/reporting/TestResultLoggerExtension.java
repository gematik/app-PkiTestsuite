/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.testsuite.reporting;

import static java.util.Collections.emptyList;

import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

@Slf4j
public class TestResultLoggerExtension implements TestWatcher {

  @Getter private static String stopExecutionOfRemainingTestsReason;

  public static void stopExecutionOfRemainingTests(final String reasonMessage) {
    stopExecutionOfRemainingTestsReason = reasonMessage;
  }

  public static void allowExecutionOfRemainingTests() {
    stopExecutionOfRemainingTestsReason = null;
  }

  public static boolean canContinueExecutionOfRemainingTests() {
    return stopExecutionOfRemainingTestsReason == null;
  }

  private static class TestResultsContainer {
    private static final List<TestResultInfo> testResultsStatusList =
        Collections.synchronizedList(new ArrayList<>());
  }

  private enum TestResultStatus {
    SUCCESSFUL,
    ABORTED,
    FAILED,
    DISABLED
  }

  private static class TestResultInfo {

    @Getter final TestResultStatus testResultStatus;
    final String className;
    final String methodName;
    final String displayName;

    public TestResultInfo(
        final TestResultStatus testResultStatus,
        final String className,
        final String methodName,
        final String displayName) {
      this.testResultStatus = testResultStatus;
      this.className = className;
      this.methodName = methodName;
      this.displayName = displayName;
    }

    @Override
    public String toString() {
      return "%s.%s (%s) - %s".formatted(className, methodName, displayName, testResultStatus);
    }
  }

  @Override
  public void testDisabled(final ExtensionContext context, final Optional<String> reason) {
    logTestResult(TestResultStatus.DISABLED, context);
    log.info(
        "Test Disabled for test {}: with reason :- {}",
        context.getDisplayName(),
        reason.orElse("No reason"));
  }

  @Override
  public void testSuccessful(final ExtensionContext context) {
    logTestResult(TestResultStatus.SUCCESSFUL, context);
  }

  @Override
  public void testAborted(final ExtensionContext context, final Throwable cause) {
    logTestResult(TestResultStatus.ABORTED, context);
  }

  @Override
  public void testFailed(final ExtensionContext context, final Throwable cause) {
    logTestResult(TestResultStatus.FAILED, context);
  }

  private void logTestResult(
      final TestResultStatus testResultStatus, final ExtensionContext context) {

    final Method method = context.getTestMethod().orElseThrow();

    final TestResultInfo testResultInfo =
        new TestResultInfo(
            testResultStatus,
            method.getDeclaringClass().getSimpleName(),
            method.getName(),
            context.getDisplayName());

    String stackTrace = "";
    if (testResultInfo.testResultStatus == TestResultStatus.FAILED) {
      stackTrace =
          PkitsTestSuiteUtils.getShortenedStackTrace(context.getExecutionException().orElseThrow());
    }

    TestResultsContainer.testResultsStatusList.add(testResultInfo);

    log.info(
        "\nTest Results ---> {}  {} <--- Test Results\n\n{}\n\n",
        StringUtils.rightPad(testResultInfo.testResultStatus.name(), 12),
        testResultInfo,
        stackTrace);

    printProgress();
  }

  public void printProgress() {

    final Map<TestResultStatus, List<TestResultInfo>> summary =
        TestResultsContainer.testResultsStatusList.stream()
            .collect(Collectors.groupingBy(TestResultInfo::getTestResultStatus));

    summary.putIfAbsent(TestResultStatus.SUCCESSFUL, emptyList());
    summary.putIfAbsent(TestResultStatus.FAILED, emptyList());
    summary.putIfAbsent(TestResultStatus.ABORTED, emptyList());
    summary.putIfAbsent(TestResultStatus.DISABLED, emptyList());

    log.info(
        """
            Test results progress:
              selected:   {}
              successful: {}
              failed:     {}
              aborted:    {}
              skipped:    {}
        """,
        TestResultsContainer.testResultsStatusList.size(),
        summary.get(TestResultStatus.SUCCESSFUL).size(),
        summary.get(TestResultStatus.FAILED).size(),
        summary.get(TestResultStatus.ABORTED).size(),
        summary.get(TestResultStatus.DISABLED).size());

    final Consumer<TestResultStatus> logSelectedTests =
        testResultStatus -> {
          final String testsToStr =
              summary.get(testResultStatus).stream()
                  .map(TestResultInfo::toString)
                  .sorted()
                  .collect(Collectors.joining("\n   "));
          if (!summary.get(testResultStatus).isEmpty()) {
            log.info("{} tests:\n   {}\n\n", testResultStatus, testsToStr);
          } else {
            log.info("{} tests:   none", testResultStatus);
          }
        };

    logSelectedTests.accept(TestResultStatus.FAILED);
    logSelectedTests.accept(TestResultStatus.ABORTED);
    logSelectedTests.accept(TestResultStatus.DISABLED);
  }
}
