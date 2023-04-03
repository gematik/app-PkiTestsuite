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

package de.gematik.pki.pkits.testsuite.approval;

import com.google.common.io.Files;
import de.gematik.pki.pkits.testsuite.approval.ListApprovalTestsAndAfos.CustomTestInfo;
import de.gematik.pki.pkits.testsuite.approval.ListApprovalTestsAndAfos.TestClassesContainer;
import de.gematik.pki.pkits.testsuite.approval.support.CustomTestExecutionListener;
import de.gematik.pki.pkits.testsuite.approval.support.TestExecutionOutcome;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.junit.platform.commons.util.ReflectionUtils;
import org.junit.platform.engine.DiscoverySelector;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import org.junit.platform.launcher.listeners.TestExecutionSummary.Failure;
import org.junit.platform.launcher.listeners.UniqueIdTrackingListener;
import picocli.CommandLine;
import picocli.CommandLine.Help.Ansi;

@Slf4j
public class PkitsTestsuiteRunner {

  private static TestPlan testPlan = null;
  private static SummaryGeneratingListener summaryGeneratingListener = null;
  private static CustomTestExecutionListener customTestExecutionListener = null;
  private static TestExecutionSummary summary = null;

  @AllArgsConstructor
  private static class InputTestInfo {
    @NonNull String className;
    @NonNull String methodName;
    boolean selected;

    @Override
    public String toString() {
      return "InputTestInfo{methodName='%s', className='%s', selected=%s}"
          .formatted(methodName, className, selected);
    }
  }

  private static List<InputTestInfo> readTest(final Path allTestsFile) throws IOException {
    final List<String> lines = Files.readLines(allTestsFile.toFile(), StandardCharsets.UTF_8);

    final List<InputTestInfo> inputTestInfoList = new ArrayList<>();

    String currentClassName = null;
    boolean classSelected = false;
    for (int i = 0; i < lines.size(); i++) {
      final String line = lines.get(i);
      log.debug("line {} - <{}>", i, line);

      if (line.isEmpty()) {
        currentClassName = null;
        classSelected = false;
        continue;
      }

      final String[] columns = StringUtils.splitByWholeSeparatorPreserveAllTokens(line, "\t");

      if (columns.length != 2) {
        final String message =
            "cannot parse file %s: wrong format of line %s".formatted(allTestsFile, i + 1);
        throw new TestSuiteException(message);
      }

      final String col1 = columns[0];
      final String col2 = columns[1];

      if (col2.startsWith("de.gematik.pki.pkits.testsuite.approval")) {
        currentClassName = col2;
        classSelected = col1.equals("+");
      } else {

        final String methodName = StringUtils.substringBefore(col2, " ");
        final boolean selected = col1.equals("+") || (classSelected && !col1.equals("-"));

        final InputTestInfo inputTestInfo =
            new InputTestInfo(currentClassName, methodName, selected);

        inputTestInfoList.add(inputTestInfo);
      }
    }

    return inputTestInfoList;
  }

  private static void printSummary() {

    final StringWriter out = new StringWriter();
    final PrintWriter writer = new PrintWriter(out);

    summary.printTo(writer);
    writer.flush();
    final String summaryStr = out.toString();

    for (final Failure failure : summary.getFailures()) {
      log.info("failure: " + failure.getTestIdentifier().getDisplayName());
    }

    log.info("Summary:\n{}", summaryStr);
  }

  static void runTests(final List<CustomTestInfo> customTestInfoList) {

    final String selectedCustomTestInfoListStr =
        customTestInfoList.stream().map(CustomTestInfo::toString).collect(Collectors.joining("\n"));

    log.info("selected tests to run:\n{}", selectedCustomTestInfoListStr);

    final List<DiscoverySelector> selectors = new ArrayList<>();

    for (final CustomTestInfo customTestInfo : customTestInfoList) {
      final String fullyQualifiedMethodName =
          ReflectionUtils.getFullyQualifiedMethodName(customTestInfo.clazz, customTestInfo.method);
      log.info("selected: " + fullyQualifiedMethodName);
      selectors.add(DiscoverySelectors.selectMethod(customTestInfo.clazz, customTestInfo.method));
    }

    final LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request().selectors(selectors).build();

    summaryGeneratingListener = new SummaryGeneratingListener();
    customTestExecutionListener = new CustomTestExecutionListener();

    final UniqueIdTrackingListener uniqueIdTrackingListener = new UniqueIdTrackingListener();

    try (final LauncherSession session = LauncherFactory.openSession()) {
      final Launcher launcher = session.getLauncher();
      // Register a listener of your choice
      launcher.registerTestExecutionListeners(
          summaryGeneratingListener, customTestExecutionListener, uniqueIdTrackingListener);

      // Discover tests and build a test plan
      testPlan = launcher.discover(request);

      // Execute test plan
      launcher.execute(testPlan);
    }
  }

  private static void printDetailed() {
    customTestExecutionListener
        .getTestExecutionOutcomes()
        .forEach(
            testExecutionOutcome -> {
              if (!testExecutionOutcome.testIdentifier.isTest()) {
                return;
              }

              final MethodSource methodSource =
                  (MethodSource) testExecutionOutcome.testIdentifier.getSource().orElseThrow();
              String furtherInfo = testExecutionOutcome.getFurtherInfo();
              furtherInfo =
                  RegExUtils.replaceAll(
                      furtherInfo,
                      "\tat (org.junit|java.base/).*",
                      "\tat <org.junit or java.base>...");
              furtherInfo =
                  RegExUtils.replaceAll(
                      furtherInfo,
                      "(\tat <org.junit or java.base>...\r?\n)+",
                      "\tat <org.junit or java.base>...X times \n");

              log.info(
                  "{}  {}  {}  {}  {}",
                  StringUtils.rightPad(testExecutionOutcome.getStatus(), 15),
                  StringUtils.rightPad(
                      ClassUtils.getShortClassName(methodSource.getClassName()), 30),
                  StringUtils.rightPad(methodSource.getMethodName(), 30),
                  testExecutionOutcome.testIdentifier.getDisplayName(),
                  furtherInfo);
            });
  }

  private static void printFailedAndAbortedShort() {

    log.info("list of failed or aborted test cases:");
    final List<TestExecutionOutcome> failedTestCases =
        customTestExecutionListener.getTestExecutionOutcomes().stream()
            .filter(
                testExecutionOutcome -> {
                  if (!testExecutionOutcome.testIdentifier.isTest()) {
                    return false;
                  }

                  return StringUtils.equalsAny(
                      testExecutionOutcome.getStatus(), "FAILED", "ABORTED");
                })
            .toList();

    failedTestCases.forEach(
        testExecutionOutcome -> {
          final MethodSource methodSource =
              (MethodSource) testExecutionOutcome.testIdentifier.getSource().orElseThrow();

          log.info(
              "{}  {}  {}  {}",
              StringUtils.rightPad(testExecutionOutcome.getStatus(), 15),
              StringUtils.rightPad(ClassUtils.getShortClassName(methodSource.getClassName()), 30),
              StringUtils.rightPad(methodSource.getMethodName(), 30),
              testExecutionOutcome.testIdentifier.getDisplayName());
        });
  }

  public static String getLog4jLoggerFileName(Class<?> clazz) {

    final LoggerContext loggerContext = (LoggerContext) LogManager.getContext(true);

    final Logger logger = loggerContext.getLogger(clazz.getCanonicalName());
    return ((FileAppender) logger.getAppenders().get("FILE")).getFileName();
  }

  static void reportAndEvaluate(final boolean skipPdfReport) throws IOException {

    summary = summaryGeneratingListener.getSummary();

    printSummary();
    printDetailed();
    printFailedAndAbortedShort();

    log.info("FINISHED MAIN with {} failures!", summary.getFailures().size());

    final StringBuilder sb = new StringBuilder();

    final BiFunction<String, Long, String> func =
        (name, count) -> {
          final double total = summary.getTestsFoundCount();
          return "%s  %d  /  %.0f%%%n".formatted(name, count, 100 * count / total);
        };
    sb.append("Tests summary:\n");

    sb.append(func.apply("found     ", summary.getTestsFoundCount()));
    sb.append(func.apply("successful", summary.getTestsSucceededCount()));
    sb.append(func.apply("failed    ", summary.getTestsFailedCount()));
    sb.append(func.apply("skipped   ", summary.getTestsSkippedCount()));

    log.info(sb.toString());
    int exitCode = 0;
    if (!summary.getFailures().isEmpty()) {
      log.error("test execution complete with failures");
      exitCode = 1;
    } else if (summary.getTestsSucceededCount() == 0) {
      log.error("0 tests were executed");
      exitCode = 1;
    } else {
      log.info("tests execution complete successfully");
    }

    if (!skipPdfReport) {
      GeneratePdf.savePdf(getLog4jLoggerFileName(PkitsTestsuiteRunner.class), false);
    } else {
      log.info("skip pdf report generation");
    }
    System.exit(exitCode);
  }

  private static List<InputTestInfo> parseTestNamesToInputTestInfos(final String testNamesStr) {
    final String[] testNames =
        StringUtils.splitByWholeSeparatorPreserveAllTokens(testNamesStr, ",");
    return Arrays.stream(testNames)
        .map(
            testName -> {
              final String classNameSeparator = "#";
              String className = "";
              String methodName = testName;
              if (testName.contains(classNameSeparator)) {
                className = StringUtils.substringBefore(testName, classNameSeparator);
                methodName = StringUtils.substringAfter(testName, classNameSeparator);
              }
              return new InputTestInfo(className, methodName, true);
            })
        .toList();
  }

  static List<CustomTestInfo> getTestToRun(
      final List<InputTestInfo> inputTestInfoList,
      final TestClassesContainer testClassesContainer) {
    final List<CustomTestInfo> customTestInfoList = testClassesContainer.getAllCustomTestInfos();

    return inputTestInfoList.stream()
        .filter(inputTestInfo -> inputTestInfo.selected)
        .map(
            inputTestInfo -> {
              for (final CustomTestInfo customTestInfo : customTestInfoList) {

                final boolean sameClassName =
                    StringUtils.isBlank(inputTestInfo.className)
                        || StringUtils.equalsAny(
                            inputTestInfo.className,
                            customTestInfo.getSimpleClassName(),
                            customTestInfo.getClassName());
                final boolean sameMethodName =
                    customTestInfo.method.getName().equals(inputTestInfo.methodName);

                if (sameClassName && sameMethodName) {
                  return customTestInfo;
                }
              }

              throw new TestSuiteException(
                  "unknown test case: %s of class %s"
                      .formatted(inputTestInfo.methodName, inputTestInfo.className));
            })
        .toList();
  }

  private static class RunnerParams {
    @CommandLine.Option(
        names = {"-tf", "--tests-file"},
        description = "the file with tests to run")
    Path testCasesFile = ListApprovalTestsAndAfos.ALL_TESTCASES_FILE;

    @CommandLine.Option(
        names = {"-tn", "--tests-names"},
        description =
            "comma separated list of names to run, for example"
                + " \"verifyConnectCertsValid,TslApprovalTestsIT,TslSignerApprovalTestsIT#checkInitialState\"")
    String testCasesNames;

    @CommandLine.Option(
        names = {"-h", "--help"},
        usageHelp = true,
        description = "display a help message")
    private boolean helpRequested = false;

    @CommandLine.Option(
        names = {"--no-pdf-report"},
        description = "Do not generate report as PDF")
    private boolean skipPdfReport = false;
  }

  public static void main(final String[] args) throws IOException {

    final RunnerParams runnerParams = new RunnerParams();
    new CommandLine(runnerParams).parseArgs(args);

    if (runnerParams.helpRequested) {
      CommandLine.usage(runnerParams, System.out, Ansi.OFF);
      return;
    }

    final List<InputTestInfo> inputTestInfoList;
    if (runnerParams.testCasesNames != null) {
      inputTestInfoList = parseTestNamesToInputTestInfos(runnerParams.testCasesNames);
    } else {
      inputTestInfoList = readTest(runnerParams.testCasesFile);
    }

    final TestClassesContainer testClassesContainer =
        TestClassesContainer.readForClassPostfixes(
            "TestsIT", "TestsBaseIT", "InitialTestDataTest", "TslVaSwitchUtils");

    final List<CustomTestInfo> selectedCustomTestInfoList =
        getTestToRun(inputTestInfoList, testClassesContainer);

    runTests(selectedCustomTestInfoList);
    reportAndEvaluate(runnerParams.skipPdfReport);
  }
}
