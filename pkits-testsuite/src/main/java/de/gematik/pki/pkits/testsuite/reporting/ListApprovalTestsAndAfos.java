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

package de.gematik.pki.pkits.testsuite.reporting;

import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.runner.CustomTestInfo;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ClassUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

@Slf4j
public class ListApprovalTestsAndAfos {

  public static final String ALL_TESTCASES_FILENAME = "./allTests.txt";
  public static final String ALL_FAILED_OR_ABORTED_TESTCASES_FILENAME = "./allFailedOrAborted.txt";
  private static final Path TEST_TO_AFOS_FILE = Path.of("./docs/afoCoverage_testToAfos.txt");
  private static final Path AFOS_DESCRIPTION_FILE =
      Path.of("./docs/afoCoverage_afoDescriptions.txt");
  private static final Path AFO_TO_TESTS_FILE = Path.of("./docs/afoCoverage_afoToTests.txt");

  private static final Set<String> testsOrClassesToSkipPerDefault = new TreeSet<>();

  static {
    testsOrClassesToSkipPerDefault.add("verifyUseCaseRsaCertValid");
  }

  public static final Predicate<CustomTestInfo> relevantCustomTestInfoPredicate =
      (customTestInfo -> !customTestInfo.getMethodName().equals("checkInitialState"));

  private static boolean isToSkipTestMethodOrClass(final String methodNameOrClass) {
    return testsOrClassesToSkipPerDefault.contains(methodNameOrClass)
        || testsOrClassesToSkipPerDefault.contains(ClassUtils.getShortClassName(methodNameOrClass));
  }

  static boolean isToVerify(final String[] args) {
    return ArrayUtils.contains(args, "--verify");
  }

  static boolean isToGenerate(final String[] args) {
    return (args.length == 0) || ArrayUtils.contains(args, "--generate");
  }

  enum ExecutionMode {
    SAVE,
    VERIFY
  }

  @AllArgsConstructor
  public static class TestClassesContainer {

    Map<String, Set<CustomTestInfo>> testClasses;

    public static TestClassesContainer readForDefaultTestClasses() {
      final Map<String, Set<CustomTestInfo>> classTestsMap =
          ListApprovalTestsAndAfos.getClassTestMap(ApprovalTestsBase.ALL_TESTS_CLASSES);
      return new TestClassesContainer(classTestsMap);
    }

    public List<CustomTestInfo> getAllCustomTestInfos() {
      return testClasses.values().stream().flatMap(Collection::stream).toList();
    }
  }

  private static List<Method> getMethodsAnnotatedWith(
      final Class<?> type, final List<Class<? extends Annotation>> annotations) {

    final List<Method> methods = new ArrayList<>();
    Class<?> clazz = type;
    while (clazz != Object.class) {
      // need to traverse a type hierarchy in order to process methods from super
      // types
      // iterate though the list of methods declared in the class represented by clazz variable, and
      // add those annotated with the specified annotation
      for (final Method method : clazz.getDeclaredMethods()) {
        boolean b = false;

        for (final Class<? extends Annotation> annotation : annotations) {
          b |= method.isAnnotationPresent(annotation);
        }

        if (b) {
          methods.add(method);
        }
      }
      // move to the upper class in the hierarchy in search for more methods
      clazz = clazz.getSuperclass();
    }
    return methods;
  }

  public static String padRight(final String s, final int n) {
    return ("%-" + n + "s").formatted(s);
  }

  static void saveOrVerifyAfosToTestsFile(
      final Map<String, Set<CustomTestInfo>> classTestMap, final ExecutionMode executionMode) {

    final Map<String, List<CustomTestInfo>> afosToCustomTestInfo = new TreeMap<>();

    final List<Afo> allAfos =
        classTestMap.values().stream()
            .flatMap(Collection::stream)
            .filter(relevantCustomTestInfoPredicate)
            .flatMap(customTestInfo -> Arrays.stream(customTestInfo.getAfos()))
            .toList();

    allAfos.forEach(afo -> afosToCustomTestInfo.put(afo.afoId(), new ArrayList<>()));

    classTestMap.values().stream()
        .flatMap(Collection::stream)
        .filter(relevantCustomTestInfoPredicate)
        .forEach(
            customTestInfo ->
                Arrays.stream(customTestInfo.getAfos())
                    .forEach(afo -> afosToCustomTestInfo.get(afo.afoId()).add(customTestInfo)));

    final List<String> lines = new ArrayList<>();

    for (final Entry<String, List<CustomTestInfo>> entry : afosToCustomTestInfo.entrySet()) {

      if (!lines.isEmpty()) {
        lines.add("");
      }

      final String afoId = entry.getKey();
      final List<CustomTestInfo> customTestInfos = entry.getValue();

      Collections.sort(customTestInfos);

      lines.add(afoId);
      customTestInfos.forEach(
          customTestInfo ->
              lines.add(
                  "  "
                      + StringUtils.substringAfterLast(customTestInfo.getClassName(), ".")
                      + "."
                      + customTestInfo.getMethodName()));
    }

    final String generatedContent =
        lines.stream().map(line -> line + "\n").collect(Collectors.joining());
    saveOrVerify(AFO_TO_TESTS_FILE, generatedContent, executionMode);
  }

  static void saveOrVerifyAfosDescriptionFile(
      final Map<String, Set<CustomTestInfo>> classTestMap, final ExecutionMode executionMode) {

    final List<Afo> allAfos =
        classTestMap.values().stream()
            .flatMap(Collection::stream)
            .filter(relevantCustomTestInfoPredicate)
            .flatMap(customTestInfo -> Arrays.stream(customTestInfo.getAfos()))
            .toList();

    final Optional<Integer> maxAfoNameLengthOpt =
        allAfos.stream().map(afo -> afo.afoId().length()).max(Comparator.naturalOrder());

    final int padN = maxAfoNameLengthOpt.orElseThrow() + 2;

    final Set<String> afoAndDescription =
        allAfos.stream()
            .map(afo -> padRight(afo.afoId(), padN) + afo.description())
            .collect(Collectors.toCollection(TreeSet::new));

    final String generatedContent =
        afoAndDescription.stream().map(line -> line + "\n").collect(Collectors.joining());

    saveOrVerify(AFOS_DESCRIPTION_FILE, generatedContent, executionMode);
  }

  static void saveOrVerifyTestToAfosFile(
      final Map<String, Set<CustomTestInfo>> classTestMap, final ExecutionMode executionMode) {
    final List<String> lines = new ArrayList<>();

    for (final Entry<String, Set<CustomTestInfo>> entry : classTestMap.entrySet()) {
      if (!lines.isEmpty()) {
        lines.add("");
      }

      lines.add(entry.getKey());
      final Optional<Integer> maxMethodNameLengthOpt =
          entry.getValue().stream()
              .map(customTestInfo -> customTestInfo.getMethodName().length())
              .max(Comparator.naturalOrder());

      final int padN = maxMethodNameLengthOpt.orElseThrow() + 2;

      entry.getValue().stream()
          .filter(relevantCustomTestInfoPredicate)
          .forEach(
              customTestInfo -> {
                final List<String> afoIds =
                    Arrays.stream(customTestInfo.getAfos()).map(Afo::afoId).sorted().toList();

                final String methodNamePadded = padRight(customTestInfo.getMethodName(), padN);
                final String line = "  %s%s".formatted(methodNamePadded, String.join(", ", afoIds));
                lines.add(line);
              });
    }

    final String generatedContent =
        lines.stream().map(line -> line + "\n").collect(Collectors.joining());
    saveOrVerify(TEST_TO_AFOS_FILE, generatedContent, executionMode);
  }

  static String customTestInfoToLine(
      final CustomTestInfo customTestInfo, final boolean skipWholeClass, final int padN) {
    String sign = "";

    final boolean skipMethod = isToSkipTestMethodOrClass(customTestInfo.getMethodName());
    if (skipWholeClass || skipMethod) {
      sign = "-";
    }

    final String methodNamePadded = padRight(customTestInfo.getMethodName(), padN);
    final String additionalInfo1 = customTestInfo.isDisabled() ? "(DISABLED) " : "";
    final String additionalInfo2 =
        customTestInfo.isParameterizedTest() ? " (multiple data variants)" : "";
    return "%s\t%s%s%s%s"
        .formatted(
            sign,
            methodNamePadded,
            additionalInfo1,
            StringUtils.defaultString(customTestInfo.getDisplayName()),
            additionalInfo2);
  }

  static String generateContentForAllTests(final Map<String, Set<CustomTestInfo>> classTestMap) {

    final List<String> lines = new ArrayList<>();

    for (final Entry<String, Set<CustomTestInfo>> entry : classTestMap.entrySet()) {
      if (!lines.isEmpty()) {
        lines.add("");
      }

      final String className = entry.getKey();
      final boolean skipWholeClass = isToSkipTestMethodOrClass(className);

      final String classLineSign = skipWholeClass ? "-" : "+";
      final String classLine = classLineSign + "\t" + className;

      lines.add(classLine);

      final Optional<Integer> maxMethodNameLengthOpt =
          entry.getValue().stream()
              .map(customTestInfo -> customTestInfo.getMethodName().length())
              .max(Comparator.naturalOrder());

      final int padN = maxMethodNameLengthOpt.orElseThrow() + 2;

      entry.getValue().stream()
          .filter(relevantCustomTestInfoPredicate)
          .map(customTestInfo -> customTestInfoToLine(customTestInfo, skipWholeClass, padN))
          .forEach(lines::add);
    }

    return lines.stream().map(line -> line + "\n").collect(Collectors.joining());
  }

  static void saveOrVerify(
      final Path file, final String generatedContent, final ExecutionMode executionMode) {
    try {

      if (executionMode == ExecutionMode.VERIFY) {
        log.info("verify if content of the file is up to date: {}", file);
        final String contentFromFile = Files.readString(file);
        if (!generatedContent.equals(contentFromFile)) {
          log.info("generatedContent:    <{}>", StringEscapeUtils.escapeJson(generatedContent));
          log.info("vs. contentFromFile: <{}>", StringEscapeUtils.escapeJson(contentFromFile));
          throw new TestSuiteException(file + " is not updated");
        }
      }

      if (executionMode == ExecutionMode.SAVE) {
        log.info("save generated content for the file: {}", file);
        Files.writeString(file, generatedContent);
      }

    } catch (final IOException e) {
      throw new TestSuiteException(e);
    }
  }

  static void saveOrVerifyAllTestsFile(
      final Map<String, Set<CustomTestInfo>> classTestMap, final ExecutionMode executionMode) {
    final String generatedContent = generateContentForAllTests(classTestMap);
    saveOrVerify(Path.of(ALL_TESTCASES_FILENAME), generatedContent, executionMode);
  }

  private static void afosCheck(final CustomTestInfo customTestInfo, final Set<String> errors) {
    if (customTestInfo.getAfos().length == 0) {
      errors.add("no AFOs specified for " + customTestInfo);
      return;
    }

    Arrays.stream(customTestInfo.getAfos())
        .filter(afo -> StringUtils.isAnyBlank(afo.afoId(), afo.description()))
        .forEach(afo -> errors.add("empty id or description in AFO of " + customTestInfo));
  }

  private static void duplicatesCheck(
      final CustomTestInfo customTestInfo,
      final String key,
      final Map<String, CustomTestInfo> testMethodNamesMap,
      final Set<String> errors) {

    if (testMethodNamesMap.containsKey(key)) {
      final CustomTestInfo badCustomTestInfo = testMethodNamesMap.get(key);
      errors.add(badCustomTestInfo + "  and  " + customTestInfo);
    } else {
      testMethodNamesMap.put(key, customTestInfo);
    }
  }

  private static void verifyEmptyAndDuplicates(
      final Map<String, Set<CustomTestInfo>> classTestsMap) {

    if (classTestsMap.isEmpty()) {
      throw new IllegalArgumentException("No tests found");
    }

    final Map<String, CustomTestInfo> testMethodNamesMap = new HashMap<>();
    final Map<String, CustomTestInfo> testDisplayNamesMap = new HashMap<>();

    final Set<String> duplicateMethodNameTests = new TreeSet<>();
    final Set<String> duplicateDisplayNameTests = new TreeSet<>();
    final Set<String> emptyDisplayNameTests = new TreeSet<>();
    final Set<String> afosChecks = new TreeSet<>();

    classTestsMap.values().stream()
        .flatMap(Collection::stream)
        .filter(relevantCustomTestInfoPredicate)
        .forEach(
            customTestInfo -> {
              afosCheck(customTestInfo, afosChecks);

              duplicatesCheck(
                  customTestInfo,
                  customTestInfo.getMethodName(),
                  testMethodNamesMap,
                  duplicateMethodNameTests);

              if (StringUtils.isBlank(customTestInfo.getDisplayName())) {
                emptyDisplayNameTests.add(customTestInfo.toString());
                return;
              }

              duplicatesCheck(
                  customTestInfo,
                  customTestInfo.getDisplayName(),
                  testDisplayNamesMap,
                  duplicateDisplayNameTests);
            });

    final List<String> errorsParts = new ArrayList<>();

    final BiConsumer<String, Set<String>> addErrorParts =
        (name, list) ->
            errorsParts.add(list.size() + " " + name + " :\n" + String.join("\n", list));

    addErrorParts.accept("emptyDisplayNameTests", emptyDisplayNameTests);
    addErrorParts.accept("duplicateMethodNameTests", duplicateMethodNameTests);
    addErrorParts.accept("duplicateDisplayNameTests", duplicateDisplayNameTests);
    addErrorParts.accept("afosChecks", afosChecks);

    final int errorsCount =
        emptyDisplayNameTests.size()
            + duplicateMethodNameTests.size()
            + duplicateDisplayNameTests.size()
            + afosChecks.size();

    if (errorsCount > 1) {
      throw new IllegalArgumentException(
          errorsCount + " issues with tests detected: \n\n" + String.join("\n\n", errorsParts));
    }
  }

  private static Map<String, Set<CustomTestInfo>> getClassTestMap(
      final List<Class<?>> testClasses) {

    final List<Class<? extends Annotation>> testAnnotations =
        List.of(Test.class, ParameterizedTest.class);

    final Map<String, Set<CustomTestInfo>> classTestsMap = new TreeMap<>();

    for (final Class<?> clazz : testClasses) {
      final List<Method> testMethods = getMethodsAnnotatedWith(clazz, testAnnotations);
      log.debug("class: {}", clazz.getCanonicalName());
      log.debug("testMethods: {}", testMethods.stream().map(Method::getName).toList());

      final TreeSet<CustomTestInfo> methodsSet =
          testMethods.stream()
              .map(
                  method -> {
                    final DisplayName displayNameAnnotation =
                        method.getAnnotation(DisplayName.class);

                    final String displayName =
                        displayNameAnnotation == null ? "" : displayNameAnnotation.value();

                    final Afo[] afos = method.getAnnotationsByType(Afo.class);

                    return new CustomTestInfo(clazz, method, displayName, afos);
                  })
              .collect(Collectors.toCollection(TreeSet::new));

      classTestsMap.put(clazz.getCanonicalName(), methodsSet);
    }

    return classTestsMap;
  }

  public static void main(final String[] args) {

    final List<Class<?>> approvalTestsClasses =
        de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ALL_TESTS_CLASSES.stream()
            .filter(
                clazz -> clazz.getPackageName().equals(ApprovalTestsBase.class.getPackageName()))
            .toList();

    final Map<String, Set<CustomTestInfo>> classTestsMap = getClassTestMap(approvalTestsClasses);

    final Consumer<ExecutionMode> saveOrVerify =
        executionMode -> {
          saveOrVerifyAllTestsFile(classTestsMap, executionMode);
          saveOrVerifyTestToAfosFile(classTestsMap, executionMode);
          saveOrVerifyAfosDescriptionFile(classTestsMap, executionMode);
          saveOrVerifyAfosToTestsFile(classTestsMap, executionMode);
        };

    if (isToVerify(args)) {
      verifyEmptyAndDuplicates(classTestsMap);
      saveOrVerify.accept(ExecutionMode.VERIFY);
    }

    if (isToGenerate(args)) {
      saveOrVerify.accept(ExecutionMode.SAVE);
    }
  }
}
