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

import java.util.ArrayList;
import java.util.List;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;

public class CustomTestExecutionListener implements TestExecutionListener {

  public List<TestExecutionOutcome> testExecutionOutcomes = new ArrayList<>();

  @Override
  public void executionFinished(
      final TestIdentifier testIdentifier, final TestExecutionResult testExecutionResult) {
    testExecutionOutcomes.add(new TestExecutionOutcome(testIdentifier, testExecutionResult));
  }

  @Override
  public void executionSkipped(final TestIdentifier testIdentifier, final String reason) {
    testExecutionOutcomes.add(new TestExecutionOutcome(testIdentifier, reason));
  }

  public List<TestExecutionOutcome> getTestExecutionOutcomes() {
    return testExecutionOutcomes;
  }
}
