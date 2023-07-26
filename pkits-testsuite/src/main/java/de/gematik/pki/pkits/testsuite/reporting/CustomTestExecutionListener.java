/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.reporting;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;

public class CustomTestExecutionListener implements TestExecutionListener {

  @Getter @Setter private static boolean stopComponentsClassAfterAll = true;
  private final Map<String, TestExecutionOutcome> testExecutionOutcomes = new LinkedHashMap<>();

  @Override
  public void executionStarted(final TestIdentifier testIdentifier) {
    final TestExecutionOutcome testExecutionOutcome = new TestExecutionOutcome(testIdentifier);
    testExecutionOutcomes.put(testIdentifier.getUniqueId(), testExecutionOutcome);

    final ZonedDateTime now = ZonedDateTime.now();
    testExecutionOutcome.setStartedAt(now);
  }

  @Override
  public void executionFinished(
      final TestIdentifier testIdentifier, final TestExecutionResult testExecutionResult) {

    final TestExecutionOutcome testExecutionOutcome =
        testExecutionOutcomes.get(testIdentifier.getUniqueId());

    final ZonedDateTime now = ZonedDateTime.now();
    testExecutionOutcome.setFinishedAt(now);

    testExecutionOutcome.setTestExecutionResult(testExecutionResult);
  }

  @Override
  public void executionSkipped(final TestIdentifier testIdentifier, final String skippedReason) {
    final TestExecutionOutcome testExecutionOutcome = new TestExecutionOutcome(testIdentifier);
    final ZonedDateTime now = ZonedDateTime.now();

    testExecutionOutcome.setStartedAt(now);
    testExecutionOutcome.setFinishedAt(now);

    testExecutionOutcome.setSkippedReason(skippedReason);
    testExecutionOutcomes.put(testIdentifier.getUniqueId(), testExecutionOutcome);
  }

  public List<TestExecutionOutcome> getTestExecutionOutcomes() {
    return new ArrayList<>(testExecutionOutcomes.values());
  }
}
