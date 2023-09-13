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

package de.gematik.pki.pkits.testsuite.runner;

import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos.TestClassesContainer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class PkitsTestsuiteRunnerUtils {

  static List<InputTestInfo> readTests(final Path allTestsFile) throws IOException {
    final List<String> lines = Files.readAllLines(allTestsFile, StandardCharsets.UTF_8);

    final List<InputTestInfo> inputTestInfoList = new ArrayList<>();

    String currentClassName = "undefined";
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

      if (col2.startsWith(ApprovalTestsBase.class.getPackageName())) {
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

  static List<InputTestInfo> parseTestNamesToInputTestInfos(final String testNamesStr) {
    final String[] testNames =
        StringUtils.splitByWholeSeparatorPreserveAllTokens(testNamesStr, ",");
    return Arrays.stream(testNames)
        .map(String::trim)
        .map(
            testOrClass -> {
              final String classNameSeparator = "#";

              String className;
              String methodName;

              if (testOrClass.contains(classNameSeparator)) {
                className = StringUtils.substringBefore(testOrClass, classNameSeparator);
                methodName = StringUtils.substringAfter(testOrClass, classNameSeparator);
              } else if (testOrClass.contains(".")) {
                try {
                  Class.forName(testOrClass);
                  className = testOrClass;
                  methodName = "";
                } catch (final ClassNotFoundException e) {
                  className = "";
                  methodName = testOrClass;
                }
              } else {
                try {
                  // assuming all approval and utils test classes are in the same package as
                  // ApprovalTestsBase
                  Class.forName(
                      ClassUtils.getPackageName(ApprovalTestsBase.class) + "." + testOrClass);
                  className = testOrClass;
                  methodName = "";
                } catch (final ClassNotFoundException e) {
                  className = "";
                  methodName = testOrClass;
                }
              }
              return new InputTestInfo(className, methodName, true);
            })
        .toList();
  }

  static List<CustomTestInfo> getTestsToRun(
      final List<InputTestInfo> inputTestInfoList,
      final TestClassesContainer testClassesContainer,
      final int percent) {

    final List<CustomTestInfo> customTestInfoList = testClassesContainer.getAllCustomTestInfos();

    final Function<InputTestInfo, Stream<CustomTestInfo>> mapInputTestInfo =
        inputTestInfo -> {
          final List<CustomTestInfo> matchedCustomTestInfos =
              customTestInfoList.stream()
                  .filter(customTestInfo -> customTestInfo.matches(inputTestInfo))
                  .toList();

          if (matchedCustomTestInfos.isEmpty()) {
            throw new TestSuiteException(
                "unknown test case method <%s> or class with test cases <%s>"
                    .formatted(inputTestInfo.methodName, inputTestInfo.className));
          }
          return matchedCustomTestInfos.stream();
        };

    final List<CustomTestInfo> allSelected =
        inputTestInfoList.stream()
            .filter(inputTestInfo -> inputTestInfo.selected)
            .flatMap(mapInputTestInfo)
            .distinct()
            .collect(Collectors.toCollection(ArrayList::new));

    final String allSelectedStr =
        customTestInfoList.stream().map(CustomTestInfo::toString).collect(Collectors.joining("\n"));

    log.info("\n\nAll selected tests,  n={}:\n{}\n\n", allSelected.size(), allSelectedStr);

    Collections.shuffle(allSelected);

    final int minTestsToSelect = Math.min(1, allSelected.size());
    final int testsToSelect =
        Math.max(minTestsToSelect, (int) Math.round(allSelected.size() * percent / 100.0));

    final List<CustomTestInfo> selectedToRun = allSelected.subList(0, testsToSelect);
    final String selectedToRunStr =
        selectedToRun.stream().map(CustomTestInfo::toString).collect(Collectors.joining("\n"));

    log.info(
        "\n\nTests to run after applying value (={}) of option -p or --percent,  n={}:\n{}\n\n",
        percent,
        selectedToRun.size(),
        selectedToRunStr);

    return selectedToRun;
  }
}
