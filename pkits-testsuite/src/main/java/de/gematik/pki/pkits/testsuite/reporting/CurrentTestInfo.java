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

package de.gematik.pki.pkits.testsuite.reporting;

import java.lang.reflect.Method;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.TestInfo;

@Getter
public class CurrentTestInfo {

  private final TestInfo testInfo;

  private int tslCounter = 1;

  public CurrentTestInfo(final TestInfo testInfo) {
    this.testInfo = testInfo;
  }

  public String getMethodName() {
    return testInfo.getTestMethod().orElseThrow().getName();
  }

  public void incrementTslCounter() {
    ++tslCounter;
  }

  public static Integer getParameterizedIndex(final TestInfo testInfo) {

    final String displayName = testInfo.getDisplayName();

    if (!StringUtils.startsWith(displayName, "[")) {
      return null;
    }

    return Integer.valueOf(StringUtils.substringBefore(displayName, "]").replace("[", ""));
  }

  public String getParameterizedIndexStr() {
    return getParameterizedIndexStr(testInfo);
  }

  public static String getParameterizedIndexStr(final TestInfo testInfo) {
    final Integer index = getParameterizedIndex(testInfo);
    if (index == null) {
      return "";
    }
    return "_p" + index;
  }

  @Override
  public String toString() {

    final Method method = testInfo.getTestMethod().orElseThrow();

    return "%s.%s  (%s)"
        .formatted(
            method.getDeclaringClass().getSimpleName(),
            method.getName(),
            testInfo.getDisplayName());
  }
}
