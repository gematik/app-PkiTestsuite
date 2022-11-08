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

package de.gematik.pki.pkits.testsuite.approval.support;

import static java.util.Collections.emptyList;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

@Slf4j
public class TestResultLoggerExtension implements TestWatcher, AfterAllCallback {

  private final List<TestResultInfo> testResultsStatusList = new ArrayList<>();

  private enum TestResultStatus {
    SUCCESSFUL,
    ABORTED,
    FAILED,
    DISABLED
  }

  private static class TestResultInfo {

    TestResultStatus testResultStatus;
    String className;
    String methodName;
    String displayName;

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

    public TestResultStatus getTestResultStatus() {
      return testResultStatus;
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

    testResultsStatusList.add(testResultInfo);
    log.info("\n\nTest {}\n\n\n", testResultInfo);
  }

  @Override
  public void afterAll(final ExtensionContext context) {
    final Map<TestResultStatus, List<TestResultInfo>> summary =
        testResultsStatusList.stream()
            .collect(Collectors.groupingBy(TestResultInfo::getTestResultStatus));

    summary.putIfAbsent(TestResultStatus.SUCCESSFUL, emptyList());
    summary.putIfAbsent(TestResultStatus.FAILED, emptyList());
    summary.putIfAbsent(TestResultStatus.ABORTED, emptyList());
    summary.putIfAbsent(TestResultStatus.DISABLED, emptyList());

    log.info(
        """
            Test result summary for {}:
              SUCCESSFUL: {}
              FAILED:     {}
              ABORTED:    {}
              DISABLED:   {}


            """,
        context.getDisplayName(),
        summary.get(TestResultStatus.SUCCESSFUL).size(),
        summary.get(TestResultStatus.FAILED).size(),
        summary.get(TestResultStatus.ABORTED).size(),
        summary.get(TestResultStatus.DISABLED).size());

    if (!summary.get(TestResultStatus.FAILED).isEmpty()) {
      log.info(
          "FAILED tests:\n   {}",
          summary.get(TestResultStatus.FAILED).stream()
              .map(TestResultInfo::toString)
              .sorted()
              .collect(Collectors.joining("   \n")));
    } else {
      log.info("FAILED tests:   none");
    }

    if (!summary.get(TestResultStatus.ABORTED).isEmpty()) {
      log.info(
          "ABORTED tests:\n   {}",
          summary.get(TestResultStatus.FAILED).stream()
              .map(TestResultInfo::toString)
              .sorted()
              .collect(Collectors.joining("   \n")));
    } else {
      log.info("ABORTED tests:   none");
    }
  }
}
