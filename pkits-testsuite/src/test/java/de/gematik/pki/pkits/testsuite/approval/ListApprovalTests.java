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

package de.gematik.pki.pkits.testsuite.approval;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
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
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

@Slf4j
public class ListApprovalTests {

  public static final String TESTCASE_FILE = "../allTest.txt";

  private List<Class> findTestClasses(final String dirname, final String[] postfixes)
      throws ClassNotFoundException, IOException {
    final List<Class> allClasses = findClasses(Path.of(dirname), "");

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
  private static List<Class> findClasses(final Path directory, final String packageName)
      throws IOException, ClassNotFoundException {

    final List<Class> classes = new ArrayList<>();
    if (!Files.exists(directory)) {
      return classes;
    }
    final List<Path> files = Files.list(directory).collect(Collectors.toList());
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

  public static List<Method> getMethodsAnnotatedWith(
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
    return String.format("%-" + n + "s", s);
  }

  static void saveToFile(final Map<String, Set<TestInfo>> classTestMap) throws IOException {

    final List<String> lines = new ArrayList<>();

    for (final Entry<String, Set<TestInfo>> entry : classTestMap.entrySet()) {
      if (!lines.isEmpty()) {
        lines.add("");
      }

      lines.add("+\t" + entry.getKey());
      final Optional<Integer> maxMethodNameLengthOpt =
          entry.getValue().stream()
              .map(testInfo -> testInfo.methodName.length())
              .max(Comparator.naturalOrder());

      final int padN = maxMethodNameLengthOpt.orElseThrow() + 2;

      entry
          .getValue()
          .forEach(
              testInfo -> {
                final String padded = padRight(testInfo.methodName, padN);
                final String line =
                    "\t%s%s".formatted(padded, StringUtils.defaultString(testInfo.displayName));
                lines.add(line);
              });
    }

    final String content = lines.stream().map(line -> line + "\n").collect(Collectors.joining());
    Files.writeString(Path.of(TESTCASE_FILE), content);
  }

  private static void verifyEmptyAndDuplicates(final Map<String, Set<TestInfo>> classTestsMap) {

    if (classTestsMap.isEmpty()) {
      throw new IllegalArgumentException("No tests found");
    }

    final Map<String, TestInfo> testMethodNamesMap = new HashMap<>();
    final Map<String, TestInfo> testDisplayNamesMap = new HashMap<>();

    final Set<String> duplicateMethodNameTests = new TreeSet<>();
    final Set<String> duplicateDisplayNameTests = new TreeSet<>();

    classTestsMap.values().stream()
        .flatMap(Collection::stream)
        .forEach(
            testInfo -> {
              if (testMethodNamesMap.containsKey(testInfo.methodName)) {
                final TestInfo duplicateTestInfo = testMethodNamesMap.get(testInfo.methodName);
                duplicateMethodNameTests.add("" + duplicateTestInfo + "  and  " + testInfo);
              } else {
                testMethodNamesMap.put(testInfo.methodName, testInfo);
              }

              if (StringUtils.isNotBlank(testInfo.displayName)
                  && testDisplayNamesMap.containsKey(testInfo.displayName)) {
                final TestInfo duplicateTestInfo = testDisplayNamesMap.get(testInfo.displayName);
                duplicateDisplayNameTests.add("" + duplicateTestInfo + "  and  " + testInfo);
              } else {
                testDisplayNamesMap.put(testInfo.displayName, testInfo);
              }
            });

    final String errors =
        duplicateMethodNameTests.size()
            + " duplicateMethodNameTests:\n"
            + String.join("\n", duplicateMethodNameTests)
            + "\n\n"
            + duplicateDisplayNameTests.size()
            + " duplicateDisplayNameTests:\n"
            + String.join("\n", duplicateDisplayNameTests);

    if (duplicateMethodNameTests.size() + duplicateDisplayNameTests.size() > 1) {
      throw new IllegalArgumentException("Duplicates found: " + errors);
    }
  }

  @AllArgsConstructor
  public static class TestInfo implements Comparable<TestInfo> {
    String className;
    String methodName;
    String displayName;

    @Override
    public int compareTo(final TestInfo o) {
      return methodName.compareTo(o.methodName);
    }

    @Override
    public String toString() {
      return "TestInfo{className='%s', methodName='%s', displayName='%s'}"
          .formatted(className, methodName, displayName);
    }
  }

  private Map<String, Set<TestInfo>> getClassTestMap(final List<Class> testClasses) {

    final List<Class<? extends Annotation>> testAnnotations =
        List.of(Test.class, ParameterizedTest.class);

    final Map<String, Set<TestInfo>> classTestsMap = new TreeMap<>();

    for (final Class clazz : testClasses) {
      final List<Method> testMethods = getMethodsAnnotatedWith(clazz, testAnnotations);
      log.info("class: {}", clazz.getCanonicalName());
      log.info("testMethods: {}", testMethods.stream().map(Method::getName).toList());

      final TreeSet<TestInfo> methodsSet =
          testMethods.stream()
              .map(
                  method -> {
                    final DisplayName displayNameAnnotation =
                        method.getAnnotation(DisplayName.class);
                    final String displayName =
                        displayNameAnnotation == null ? "" : displayNameAnnotation.value();
                    return new TestInfo(clazz.getCanonicalName(), method.getName(), displayName);
                  })
              .collect(Collectors.toCollection(TreeSet::new));

      classTestsMap.put(clazz.getCanonicalName(), methodsSet);
    }

    return classTestsMap;
  }

  @Test
  void generate() throws ClassNotFoundException, IOException {

    final String[] postfixes = {"TestIT"};
    final List<Class> testClasses = findTestClasses("target/test-classes/", postfixes);

    final List<String> classesNames = testClasses.stream().map(Class::getCanonicalName).toList();

    log.info("classesNames.size(): {}", classesNames.size());
    log.info("classesNames: {}", String.join("\n", classesNames));

    final Map<String, Set<TestInfo>> classTestsMap = getClassTestMap(testClasses);

    verifyEmptyAndDuplicates(classTestsMap);
    saveToFile(classTestsMap);
  }
}
