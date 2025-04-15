/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.testsuite.runner;

import static de.gematik.pki.pkits.testsuite.reporting.GeneratePdf.htmlBr;
import static de.gematik.pki.pkits.testsuite.reporting.GeneratePdf.htmlHeader;
import static de.gematik.pki.pkits.testsuite.reporting.GeneratePdf.htmlPre;
import static de.gematik.pki.pkits.testsuite.reporting.GeneratePdf.htmlTt;
import static de.gematik.pki.pkits.testsuite.reporting.GeneratePdf.toHtml;

import com.github.dtmo.jfiglet.FigFontResources;
import com.github.dtmo.jfiglet.FigletRenderer;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsCommonUtils.GitProperties;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.reporting.CustomTestExecutionListener;
import de.gematik.pki.pkits.testsuite.reporting.GeneratePdf;
import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos;
import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos.TestClassesContainer;
import de.gematik.pki.pkits.testsuite.reporting.TestExecutionOutcome;
import de.gematik.pki.pkits.testsuite.simulators.OcspResponderInstance;
import de.gematik.pki.pkits.testsuite.simulators.TslProviderInstance;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.jar.Attributes;
import java.util.jar.Attributes.Name;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ClassUtils;
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
import org.junit.platform.launcher.listeners.UniqueIdTrackingListener;
import picocli.CommandLine;
import picocli.CommandLine.Help.Ansi;

@Slf4j
public class PkitsTestsuiteRunner {

  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  private static SummaryGeneratingListener summaryGeneratingListener = null;
  private static CustomTestExecutionListener customTestExecutionListener = null;

  private static final FigletRenderer figletRenderer;

  static {
    figletRenderer = getFigletRenderer(FigFontResources.STANDARD_FLF);
  }

  public static String toBanner(final String msg) {
    return figletRenderer.renderText(msg);
  }

  public static FigletRenderer getFigletRenderer(final String fontName) {
    try {
      return new FigletRenderer(FigFontResources.loadFigFontResource(fontName));
    } catch (final IOException e) {
      throw new TestSuiteException("Unable to load font " + fontName, e);
    }
  }

  static void runTests(final List<CustomTestInfo> customTestInfoList) {

    final List<DiscoverySelector> selectors = new ArrayList<>();

    for (final CustomTestInfo customTestInfo : customTestInfoList) {
      final String fullyQualifiedMethodName =
          ReflectionUtils.getFullyQualifiedMethodName(customTestInfo.clazz, customTestInfo.method);
      log.debug("selected: {}", fullyQualifiedMethodName);
      selectors.add(DiscoverySelectors.selectMethod(customTestInfo.clazz, customTestInfo.method));
    }

    final LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request().selectors(selectors).build();

    summaryGeneratingListener = new SummaryGeneratingListener();
    customTestExecutionListener = new CustomTestExecutionListener();

    final UniqueIdTrackingListener uniqueIdTrackingListener = new UniqueIdTrackingListener();

    CustomTestExecutionListener.setStopComponentsClassAfterAll(false);
    try (final LauncherSession session = LauncherFactory.openSession()) {
      final Launcher launcher = session.getLauncher();
      // Register a listener of your choice
      launcher.registerTestExecutionListeners(
          summaryGeneratingListener, customTestExecutionListener, uniqueIdTrackingListener);

      // Discover tests and build a test plan
      final TestPlan testPlan = launcher.discover(request);

      // Execute test plan
      launcher.execute(testPlan);
    } catch (final Exception e) {
      log.error("problems occurred executing tests", e);
    }

    CustomTestExecutionListener.setStopComponentsClassAfterAll(true);
    OcspResponderInstance.getInstance().stopServer();
    TslProviderInstance.getInstance().stopServer();
  }

  private static final int COLUMN_SIZE_STATUS = 15;
  private static final int COLUMN_SIZE_CLASS_NAME = 30;
  private static final int COLUMN_SIZE_METHOD_NAME = 50;

  static String getDetailsRow(
      final String startedAt,
      final String status,
      final String className,
      final String methodName,
      final String displayName) {
    return "%s  %s  %s  %s  %s"
        .formatted(
            startedAt,
            StringUtils.rightPad(status, COLUMN_SIZE_STATUS),
            StringUtils.rightPad(ClassUtils.getShortClassName(className), COLUMN_SIZE_CLASS_NAME),
            StringUtils.rightPad(methodName, COLUMN_SIZE_METHOD_NAME),
            displayName);
  }

  private static String getDetails() {
    final List<String> parts = new ArrayList<>();

    customTestExecutionListener
        .getTestExecutionOutcomes()
        .forEach(
            testExecutionOutcome -> {
              if (!testExecutionOutcome.getTestIdentifier().isTest()) {
                return;
              }

              final MethodSource methodSource = testExecutionOutcome.getMethodSource();

              parts.add(
                  getDetailsRow(
                      testExecutionOutcome.getStartedAt().format(dateTimeFormatter),
                      testExecutionOutcome.getStatus(),
                      methodSource.getClassName(),
                      methodSource.getMethodName(),
                      testExecutionOutcome.getDisplayName()));
            });
    final String header = htmlHeader(2, "Tests Execution Results:");
    final String columnNames =
        htmlTt(
            toHtml(
                getDetailsRow(
                    "startedAt          ", "status", "className", "methodName", "displayName")));

    return String.join(
        "\n",
        header,
        columnNames,
        htmlBr(),
        htmlTt(GeneratePdf.toHtml(String.join("\n", parts))),
        htmlBr());
  }

  private static List<TestExecutionOutcome> getFailedOrAbortedTestCases() {
    return customTestExecutionListener.getTestExecutionOutcomes().stream()
        .filter(
            testExecutionOutcome -> {
              if (!testExecutionOutcome.getTestIdentifier().isTest()) {
                return false;
              }
              return StringUtils.equalsAny(testExecutionOutcome.getStatus(), "FAILED", "ABORTED");
            })
        .toList();
  }

  private static String getFailedAndAbortedShort() {

    final List<String> parts = new ArrayList<>();

    final List<TestExecutionOutcome> failedOrAbortedTestCases = getFailedOrAbortedTestCases();

    failedOrAbortedTestCases.forEach(
        testExecutionOutcome -> {
          final MethodSource methodSource = testExecutionOutcome.getMethodSource();

          parts.add(
              getDetailsRow(
                      testExecutionOutcome.getStartedAt().format(dateTimeFormatter),
                      testExecutionOutcome.getStatus(),
                      ClassUtils.getShortClassName(methodSource.getClassName()),
                      methodSource.getMethodName(),
                      testExecutionOutcome.getDisplayName())
                  + "\n"
                  + testExecutionOutcome.getFurtherInfo());
        });

    final String separator = "\n" + StringUtils.repeat("=", 120) + StringUtils.repeat("\n", 3);
    final String testResults = String.join(separator, parts);

    final String header =
        htmlHeader(2, failedOrAbortedTestCases.size() + " Failed / Aborted Tests - Details:");
    return header + "\n" + htmlTt(GeneratePdf.toHtml(testResults)) + htmlBr();
  }

  static List<String> getTestExecutionResultsToReport(
      final TestExecutionSummary summary, final boolean noHtml) {
    final List<String> resultsReportParts = new ArrayList<>();
    final boolean oldWithHtml = GeneratePdf.isNoHtml();

    GeneratePdf.setNoHtml(noHtml);

    resultsReportParts.add(getCustomSummary(summary));
    resultsReportParts.add(getDetails());
    resultsReportParts.add(getFailedAndAbortedShort());

    GeneratePdf.setNoHtml(oldWithHtml);
    return resultsReportParts;
  }

  public static Path getLog4jLoggerFileName(final Class<?> clazz) {

    final LoggerContext loggerContext = (LoggerContext) LogManager.getContext(true);

    final Logger logger = loggerContext.getLogger(clazz.getCanonicalName());
    final String logFilename = ((FileAppender) logger.getAppenders().get("FILE")).getFileName();
    return Path.of(logFilename);
  }

  private static String getCustomSummary(final TestExecutionSummary summary) {

    final BiFunction<String, Long, String> func =
        (name, count) -> {
          final double total = summary.getTestsFoundCount();
          return "%s  %3d  /  %3.0f%%".formatted(name, count, 100 * count / total);
        };

    final List<String> parts = new ArrayList<>();

    parts.add(func.apply("selected:  ", summary.getTestsFoundCount()));
    parts.add(func.apply("successful:", summary.getTestsSucceededCount()));
    parts.add(func.apply("failed:    ", summary.getTestsFailedCount()));
    parts.add(func.apply("aborted:   ", summary.getTestsAbortedCount()));
    parts.add(func.apply("skipped:   ", summary.getTestsSkippedCount()));

    final String header = htmlHeader(2, "Tests Execution Summary:");
    return header + "\n" + htmlPre(String.join("\n", parts)) + htmlBr();
  }

  static void reportAndEvaluate(final boolean skipPdfReport) throws IOException {

    final TestExecutionSummary summary = summaryGeneratingListener.getSummary();

    int exitCode = 0;
    if (!summary.getFailures().isEmpty()) {
      log.error("Tests execution completed with failures.");
      exitCode = 1;
    } else if (summary.getTestsSucceededCount() == 0) {
      log.error("0 tests were executed.");
      exitCode = 1;
    } else {
      log.info("Tests execution completed successfully.");
    }

    final String configContent =
        Files.readString(TestSuiteConstants.PKITS_CFG_FILE_PATH, StandardCharsets.UTF_8);

    if (!skipPdfReport) {

      GeneratePdf.setNoHtml(false);
      final List<String> contentParts = new ArrayList<>();
      contentParts.add(GeneratePdf.htmlDocPrefix());
      contentParts.add(htmlTt(GeneratePdf.toHtml(getPkiTestsuiteBanner())));

      contentParts.add(htmlHeader(2, "Configuration:"));
      contentParts.add(htmlPre(configContent));
      contentParts.add(htmlBr());

      contentParts.addAll(getTestExecutionResultsToReport(summary, false));

      final Path logFile = getLog4jLoggerFileName(PkitsTestsuiteRunner.class);
      final String logContent = Files.readString(logFile, StandardCharsets.UTF_8);

      contentParts.add(htmlHeader(2, "Test Suite Log:"));
      contentParts.add(htmlTt(GeneratePdf.toHtml(logContent)));
      contentParts.add(GeneratePdf.htmlDocPostfix());
      contentParts.add(htmlBr());

      final Path baseFilename = GeneratePdf.prepareReportDirAndGetBaseFilename(logFile);
      final String pdfContent = String.join("\n\n\n", contentParts);

      GeneratePdf.saveHtmlAndPdf(pdfContent, baseFilename, true);
    } else {
      log.info("skip pdf report generation");
    }

    log.info("\n{}\n\n", String.join("\n\n\n", getTestExecutionResultsToReport(summary, true)));
    log.info("end of report");
    System.exit(exitCode);
  }

  static String getPkiTestsuiteBanner() {

    final Attributes attributes =
        PkitsCommonUtils.readManifestAttributes(PkitsTestsuiteRunner.class);
    final String title = attributes.getValue(Name.IMPLEMENTATION_TITLE);
    final String version = attributes.getValue(Name.IMPLEMENTATION_VERSION);

    final GitProperties gitProperties =
        PkitsCommonUtils.readGitProperties(PkitsTestsuiteRunner.class);

    final String versionAndCommitId =
        "Version: " + version + " (Commit Id: " + gitProperties.getCommitIdShort() + ")";

    return String.join("\n", toBanner("PKI Test Suite"), title, versionAndCommitId);
  }

  static String getSummaryForFailedOrAborted() {
    final List<TestExecutionOutcome> failedOrAbortedTestCases = getFailedOrAbortedTestCases();

    final List<String> lines =
        failedOrAbortedTestCases.stream()
            .map(
                testExecutionOutcome -> {
                  final MethodSource methodSource = testExecutionOutcome.getMethodSource();

                  final String sign = "+";
                  final int padN = 50;

                  final String methodNamePadded =
                      ListApprovalTestsAndAfos.padRight(methodSource.getMethodName(), padN);

                  return "%s\t%s   %s %s  %s"
                      .formatted(
                          sign,
                          methodNamePadded,
                          testExecutionOutcome.getStatus(),
                          ClassUtils.getShortClassName(methodSource.getClassName()),
                          testExecutionOutcome.getDisplayName());
                })
            .toList();

    return String.join("\n", lines);
  }

  public static void main(final String[] args) throws IOException {

    log.info("\n\n{}\n\n", getPkiTestsuiteBanner());

    final PkitsTestsuiteRunnerParams runnerParams = new PkitsTestsuiteRunnerParams();
    new CommandLine(runnerParams).parseArgs(args);

    if (runnerParams.isHelpRequested()) {
      CommandLine.usage(runnerParams, System.out, Ansi.OFF); // NOSONAR squid:S106
      return;
    }

    final List<InputTestInfo> inputTestInfoList;
    if (runnerParams.testCasesNames != null) {
      inputTestInfoList =
          PkitsTestsuiteRunnerUtils.parseTestNamesToInputTestInfos(runnerParams.testCasesNames);
    } else {
      inputTestInfoList = PkitsTestsuiteRunnerUtils.readTests(runnerParams.testCasesFile);
    }

    final TestClassesContainer testClassesContainer =
        TestClassesContainer.readForDefaultTestClasses();

    final List<CustomTestInfo> testsToRun =
        PkitsTestsuiteRunnerUtils.getTestsToRun(inputTestInfoList, testClassesContainer);

    runTests(testsToRun);

    if (runnerParams.failedTestCases != null) {
      final String content = getSummaryForFailedOrAborted();
      Files.writeString(runnerParams.failedTestCases, content);
    }
    reportAndEvaluate(runnerParams.isSkipPdfReport());
  }
}
