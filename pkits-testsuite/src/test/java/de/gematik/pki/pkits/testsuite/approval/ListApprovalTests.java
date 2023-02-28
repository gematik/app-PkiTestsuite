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

import de.gematik.pki.pkits.testsuite.config.Afo;
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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiConsumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

@Slf4j
class ListApprovalTests {

  private static final String ALL_TESTCASES_FILENAME = "../allTests.txt";
  private static final String TEST_TO_AFOS_FILENAME = "../docs/afoCoverage_testToAfos.txt";
  private static final String AFOS_DESCRIPTION_FILENAME = "../docs/afoCoverage_afoDescriptions.txt";
  private static final String AFO_TO_TESTS_FILENAME = "../docs/afoCoverage_afoToTests.txt";

  private List<Class<?>> findTestClasses(final String dirname, final String[] postfixes)
      throws ClassNotFoundException, IOException {
    final List<Class<?>> allClasses = findClasses(Path.of(dirname), "");

    return allClasses.stream()
        .filter(clazz -> clazz.getCanonicalName() != null)
        .filter(clazz -> StringUtils.endsWithAny(clazz.getName(), postfixes))
        .toList();
  }
  /**
   * Recursive method used to find all classes in a given directory and subdirs.
   *
   * @param directory The base directory
   * @param packageName The package name for classes found inside the base directory
   * @return The classes
   * @throws ClassNotFoundException thrown, if no class can be found for the package
   */
  private static List<Class<?>> findClasses(final Path directory, final String packageName)
      throws IOException, ClassNotFoundException {

    final List<Class<?>> classes = new ArrayList<>();
    if (!Files.exists(directory)) {
      return classes;
    }

    final List<Path> files;
    try (final Stream<Path> pathStream = Files.list(directory)) {
      files = pathStream.collect(Collectors.toList());
    }
    for (final Path file : Objects.requireNonNull(files)) {
      final String filename = file.getFileName().toString();
      if (Files.isDirectory(file)) {
        assert !filename.contains(".");

        final String className = packageName + (packageName.isEmpty() ? "" : ".") + filename;

        classes.addAll(findClasses(file, className));
      } else if (filename.endsWith(".class")) {
        final String className = packageName + '.' + filename.substring(0, filename.length() - 6);
        final Class<?> clazz = Class.forName(className);
        classes.add(clazz);
      }
    }
    return classes;
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

  private static String padRight(final String s, final int n) {
    return String.format("%-" + n + "s", s);
  }

  private static final Predicate<CustomTestInfo> relevantCustomTestInfoPredicate =
      (customTestInfo -> !customTestInfo.methodName.equals("checkInitialState"));

  static void saveAfosToTestsFile(final Map<String, Set<CustomTestInfo>> classTestMap)
      throws IOException {

    final Map<String, List<CustomTestInfo>> afosToCustomTestInfo = new TreeMap<>();

    final List<Afo> allAfos =
        classTestMap.values().stream()
            .flatMap(Collection::stream)
            .filter(relevantCustomTestInfoPredicate)
            .flatMap(customTestInfo -> Arrays.stream(customTestInfo.afos))
            .toList();

    allAfos.forEach(afo -> afosToCustomTestInfo.put(afo.afoId(), new ArrayList<>()));

    classTestMap.values().stream()
        .flatMap(Collection::stream)
        .filter(relevantCustomTestInfoPredicate)
        .forEach(
            customTestInfo ->
                Arrays.stream(customTestInfo.afos)
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
                      + StringUtils.substringAfterLast(customTestInfo.className, ".")
                      + "."
                      + customTestInfo.methodName));
    }

    final String content = lines.stream().map(line -> line + "\n").collect(Collectors.joining());
    Files.writeString(Path.of(AFO_TO_TESTS_FILENAME), content);
  }

  static void saveAfosDescriptionFile(final Map<String, Set<CustomTestInfo>> classTestMap)
      throws IOException {

    final List<Afo> allAfos =
        classTestMap.values().stream()
            .flatMap(Collection::stream)
            .filter(relevantCustomTestInfoPredicate)
            .flatMap(customTestInfo -> Arrays.stream(customTestInfo.afos))
            .toList();

    final Optional<Integer> maxAfoNameLengthOpt =
        allAfos.stream().map(afo -> afo.afoId().length()).max(Comparator.naturalOrder());

    final int padN = maxAfoNameLengthOpt.orElseThrow() + 2;

    final Set<String> afoAndDescription =
        allAfos.stream()
            .map(afo -> padRight(afo.afoId(), padN) + afo.description())
            .collect(Collectors.toCollection(TreeSet::new));

    final String content =
        afoAndDescription.stream().map(line -> line + "\n").collect(Collectors.joining());
    Files.writeString(Path.of(AFOS_DESCRIPTION_FILENAME), content);
  }

  static void saveTestToAfosFile(final Map<String, Set<CustomTestInfo>> classTestMap)
      throws IOException {
    final List<String> lines = new ArrayList<>();

    for (final Entry<String, Set<CustomTestInfo>> entry : classTestMap.entrySet()) {
      if (!lines.isEmpty()) {
        lines.add("");
      }

      lines.add(entry.getKey());
      final Optional<Integer> maxMethodNameLengthOpt =
          entry.getValue().stream()
              .map(customTestInfo -> customTestInfo.methodName.length())
              .max(Comparator.naturalOrder());

      final int padN = maxMethodNameLengthOpt.orElseThrow() + 2;

      entry.getValue().stream()
          .filter(relevantCustomTestInfoPredicate)
          .forEach(
              customTestInfo -> {
                final List<String> afoIds =
                    Arrays.stream(customTestInfo.afos).map(Afo::afoId).sorted().toList();

                final String methodNamePadded = padRight(customTestInfo.methodName, padN);
                final String line = "  %s%s".formatted(methodNamePadded, String.join(", ", afoIds));
                lines.add(line);
              });
    }

    final String content = lines.stream().map(line -> line + "\n").collect(Collectors.joining());
    Files.writeString(Path.of(TEST_TO_AFOS_FILENAME), content);
  }

  static void saveAllTestsFile(final Map<String, Set<CustomTestInfo>> classTestMap)
      throws IOException {

    final List<String> lines = new ArrayList<>();

    for (final Entry<String, Set<CustomTestInfo>> entry : classTestMap.entrySet()) {
      if (!lines.isEmpty()) {
        lines.add("");
      }

      lines.add("+\t" + entry.getKey());
      final Optional<Integer> maxMethodNameLengthOpt =
          entry.getValue().stream()
              .map(customTestInfo -> customTestInfo.methodName.length())
              .max(Comparator.naturalOrder());

      final int padN = maxMethodNameLengthOpt.orElseThrow() + 2;

      entry.getValue().stream()
          .filter(relevantCustomTestInfoPredicate)
          .forEach(
              customTestInfo -> {
                final String sign = "";
                final String methodNamePadded = padRight(customTestInfo.methodName, padN);
                final String line =
                    "%s\t%s%s"
                        .formatted(
                            sign,
                            methodNamePadded,
                            StringUtils.defaultString(customTestInfo.displayName));
                lines.add(line);
              });
    }

    final String content = lines.stream().map(line -> line + "\n").collect(Collectors.joining());
    Files.writeString(Path.of(ALL_TESTCASES_FILENAME), content);
  }

  private static void afosCheck(final CustomTestInfo customTestInfo, final Set<String> errors) {
    if (customTestInfo.afos.length == 0) {
      errors.add("no AFOs specified for " + customTestInfo);
      return;
    }

    Arrays.stream(customTestInfo.afos)
        .filter(afo -> StringUtils.isAnyBlank(afo.afoId(), afo.description()))
        .forEach(afo -> errors.add("empty id or description in AFO of " + customTestInfo));
  }

  private static void duplicatesCheck(
      final CustomTestInfo customTestInfo,
      final String key,
      final Map<String, CustomTestInfo> map,
      final Set<String> errors) {
    if (map.containsKey(key)) {

      if (customTestInfo.className.equals(customTestInfo.declaringClassName)) {
        final CustomTestInfo badCustomTestInfo = map.get(key);
        errors.add(badCustomTestInfo + "  and  " + customTestInfo);
      }
    } else {
      map.put(key, customTestInfo);
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
        .forEach(
            customTestInfo -> {
              afosCheck(customTestInfo, afosChecks);

              duplicatesCheck(
                  customTestInfo,
                  customTestInfo.methodName,
                  testMethodNamesMap,
                  duplicateMethodNameTests);

              if (StringUtils.isBlank(customTestInfo.displayName)) {
                emptyDisplayNameTests.add(customTestInfo.toString());
                return;
              }

              duplicatesCheck(
                  customTestInfo,
                  customTestInfo.displayName,
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
            + duplicateDisplayNameTests.size();
    // + afosChecks.size(); // TODO enable after AFOs are specified for all test cases

    if (errorsCount > 1) {
      throw new IllegalArgumentException(
          errorsCount + " issues with tests detected: \n\n" + String.join("\n\n", errorsParts));
    }
  }

  @AllArgsConstructor
  private static class CustomTestInfo implements Comparable<CustomTestInfo> {
    String className;
    String declaringClassName;
    String methodName;
    String displayName;
    Afo[] afos;

    @Override
    public int compareTo(final CustomTestInfo o) {
      return new CompareToBuilder()
          .append(this.className, o.className)
          .append(this.methodName, o.methodName)
          .toComparison();
    }

    @Override
    public String toString() {
      return "TestInfo{className='%s', declaringClassName='%s', methodName='%s', displayName='%s'}"
          .formatted(className, declaringClassName, methodName, displayName);
    }
  }

  private Map<String, Set<CustomTestInfo>> getClassTestMap(final List<Class<?>> testClasses) {

    final List<Class<? extends Annotation>> testAnnotations =
        List.of(Test.class, ParameterizedTest.class);

    final Map<String, Set<CustomTestInfo>> classTestsMap = new TreeMap<>();

    for (final Class<?> clazz : testClasses) {
      final List<Method> testMethods = getMethodsAnnotatedWith(clazz, testAnnotations);
      log.info("class: {}", clazz.getCanonicalName());
      log.info("testMethods: {}", testMethods.stream().map(Method::getName).toList());

      final TreeSet<CustomTestInfo> methodsSet =
          testMethods.stream()
              .map(
                  method -> {
                    final DisplayName displayNameAnnotation =
                        method.getAnnotation(DisplayName.class);

                    final String displayName =
                        displayNameAnnotation == null ? "" : displayNameAnnotation.value();

                    final String declaringClassName = method.getDeclaringClass().getCanonicalName();

                    final Afo[] afos = method.getAnnotationsByType(Afo.class);

                    return new CustomTestInfo(
                        clazz.getCanonicalName(),
                        declaringClassName,
                        method.getName(),
                        displayName,
                        afos);
                  })
              .collect(Collectors.toCollection(TreeSet::new));

      classTestsMap.put(clazz.getCanonicalName(), methodsSet);
    }

    return classTestsMap;
  }

  @Test
  void generate() throws ClassNotFoundException, IOException {

    final String[] postfixes = {"TestsIT"};
    final List<Class<?>> testClasses = findTestClasses("target/test-classes/", postfixes);

    final List<String> classesNames = testClasses.stream().map(Class::getCanonicalName).toList();

    log.info("classesNames.size(): {}", classesNames.size());
    log.info("classesNames: {}", String.join("\n", classesNames));

    final Map<String, Set<CustomTestInfo>> classTestsMap = getClassTestMap(testClasses);

    verifyEmptyAndDuplicates(classTestsMap);

    saveAllTestsFile(classTestsMap);
    saveTestToAfosFile(classTestsMap);
    saveAfosDescriptionFile(classTestsMap);
    saveAfosToTestsFile(classTestsMap);
  }
}
