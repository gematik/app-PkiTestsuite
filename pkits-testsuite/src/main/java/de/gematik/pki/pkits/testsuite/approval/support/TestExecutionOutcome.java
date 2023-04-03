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

package de.gematik.pki.pkits.testsuite.approval.support;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestIdentifier;

public class TestExecutionOutcome {

  public TestIdentifier testIdentifier;
  public TestExecutionResult testExecutionResult = null;

  public String reason;

  public boolean isSkipped() {
    return reason != null;
  }

  public String getStatus() {
    if (isSkipped()) {
      return "SKIPPED";
    }

    return "" + testExecutionResult.getStatus();
  }

  public String getFurtherInfo() {

    if (isSkipped()) {
      return reason;
    }

    if (testExecutionResult.getThrowable().isEmpty()) {
      return "";
    }

    return ExceptionUtils.getStackTrace(testExecutionResult.getThrowable().orElseThrow());
  }

  public TestExecutionOutcome(
      final TestIdentifier testIdentifier, final TestExecutionResult testExecutionResult) {
    this.testIdentifier = testIdentifier;
    this.testExecutionResult = testExecutionResult;
  }

  public TestExecutionOutcome(final TestIdentifier testIdentifier, final String reason) {
    this.testIdentifier = testIdentifier;
    this.reason = reason;
  }
}
