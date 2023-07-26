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

package de.gematik.pki.pkits.testsuite.testutils;

import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
@DisplayName("PKI check initial state.")
@Order(1)
public class InitialStateTest extends ApprovalTestsBase {

  @Test
  @Order(1)
  @DisplayName("Check initial state")
  void checkInitialState() {

    retrieveCurrentTslSeqNrInTestObject();
    initialState();
  }
}
