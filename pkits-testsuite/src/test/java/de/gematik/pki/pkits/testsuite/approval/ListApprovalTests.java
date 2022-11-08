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
class ListApprovalTests {

  private static final String TESTCASE_FILE = "../allTest.txt";

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

  static void saveToFile(final Map<String, Set<CustomTestInfo>> classTestMap) throws IOException {

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

      entry
          .getValue()
          .forEach(
              customTestInfo -> {
                if (customTestInfo.methodName.equals("checkInitialState")) {
                  return;
                }

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
    Files.writeString(Path.of(TESTCASE_FILE), content);
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

    classTestsMap.values().stream()
        .flatMap(Collection::stream)
        .forEach(
            customTestInfo -> {
              if (testMethodNamesMap.containsKey(customTestInfo.methodName)) {

                if (customTestInfo.className.equals(customTestInfo.declaringClassName)) {
                  final CustomTestInfo duplicateCustomTestInfo =
                      testMethodNamesMap.get(customTestInfo.methodName);
                  duplicateMethodNameTests.add(
                      "" + duplicateCustomTestInfo + "  and  " + customTestInfo);
                }
              } else {
                testMethodNamesMap.put(customTestInfo.methodName, customTestInfo);
              }

              if (StringUtils.isNotBlank(customTestInfo.displayName)
                  && testDisplayNamesMap.containsKey(customTestInfo.displayName)) {

                if (customTestInfo.className.equals(customTestInfo.declaringClassName)) {
                  final CustomTestInfo duplicateCustomTestInfo =
                      testDisplayNamesMap.get(customTestInfo.displayName);
                  duplicateDisplayNameTests.add(
                      "" + duplicateCustomTestInfo + "  and  " + customTestInfo);
                }
              } else {
                testDisplayNamesMap.put(customTestInfo.displayName, customTestInfo);
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
  private static class CustomTestInfo implements Comparable<CustomTestInfo> {
    String className;
    String declaringClassName;
    String methodName;
    String displayName;

    @Override
    public int compareTo(final CustomTestInfo o) {
      return methodName.compareTo(o.methodName);
    }

    @Override
    public String toString() {
      return "TestInfo{className='%s', declaringClassName='%s', methodName='%s', displayName='%s'}"
          .formatted(className, declaringClassName, methodName, displayName);
    }
  }

  private Map<String, Set<CustomTestInfo>> getClassTestMap(final List<Class> testClasses) {

    final List<Class<? extends Annotation>> testAnnotations =
        List.of(Test.class, ParameterizedTest.class);

    final Map<String, Set<CustomTestInfo>> classTestsMap = new TreeMap<>();

    for (final Class clazz : testClasses) {
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

                    return new CustomTestInfo(
                        clazz.getCanonicalName(),
                        declaringClassName,
                        method.getName(),
                        displayName);
                  })
              .collect(Collectors.toCollection(TreeSet::new));

      classTestsMap.put(clazz.getCanonicalName(), methodsSet);
    }

    return classTestsMap;
  }

  @Test
  void generate() throws ClassNotFoundException, IOException {

    final String[] postfixes = {"TestsIT"};
    final List<Class> testClasses = findTestClasses("target/test-classes/", postfixes);

    final List<String> classesNames = testClasses.stream().map(Class::getCanonicalName).toList();

    log.info("classesNames.size(): {}", classesNames.size());
    log.info("classesNames: {}", String.join("\n", classesNames));

    final Map<String, Set<CustomTestInfo>> classTestsMap = getClassTestMap(testClasses);

    verifyEmptyAndDuplicates(classTestsMap);
    saveToFile(classTestsMap);
  }
}
