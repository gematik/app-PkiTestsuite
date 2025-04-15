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

import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import java.time.ZonedDateTime;
import lombok.Getter;
import lombok.Setter;
import org.junit.jupiter.api.DisplayName;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.TestIdentifier;

@Getter
@Setter
public class TestExecutionOutcome {

  private TestIdentifier testIdentifier;
  private TestExecutionResult testExecutionResult = null;
  private String skippedReason = null;

  private ZonedDateTime startedAt;
  private ZonedDateTime finishedAt;

  TestExecutionOutcome(final TestIdentifier testIdentifier) {
    this.testIdentifier = testIdentifier;
  }

  public boolean isSkipped() {
    return skippedReason != null;
  }

  public String getStatus() {

    if (isSkipped()) {
      return "SKIPPED";
    }

    if (testExecutionResult == null) {
      return "";
    }

    return String.valueOf(testExecutionResult.getStatus());
  }

  public String getFurtherInfo() {
    if (isSkipped()) {
      return skippedReason;
    }

    if (testExecutionResult == null) {
      return "";
    }

    if (testExecutionResult.getThrowable().isEmpty()) {
      return "";
    }

    return PkitsTestSuiteUtils.getShortenedStackTrace(
        testExecutionResult.getThrowable().orElseThrow());
  }

  public String getDisplayName() {

    String displayName =
        getMethodSource().getJavaMethod().getDeclaredAnnotation(DisplayName.class).value();

    // for parameterized tests
    if (!displayName.equals(testIdentifier.getDisplayName())) {
      displayName = testIdentifier.getDisplayName() + " -- " + displayName;
    }
    return displayName;
  }

  public boolean isTest() {
    return testIdentifier.isTest();
  }

  public MethodSource getMethodSource() {
    return (MethodSource) testIdentifier.getSource().orElseThrow();
  }
}
