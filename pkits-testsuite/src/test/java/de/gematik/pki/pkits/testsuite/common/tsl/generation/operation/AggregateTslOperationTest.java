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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AggregateTslOperationTest {

  @Test
  void testRemove() {

    final AggregateTslOperation aggregate0 =
        new AggregateTslOperation(
            new PersistTslOperation(null, "tslName"),
            new ChangNameTslOperation("dummy1"),
            new BreakSignerTslOperation());

    final AggregateTslOperation aggregate1 =
        new AggregateTslOperation(
            new PersistTslOperation(null, "tslName"),
            new ChangNameTslOperation("dummy2"),
            new BreakSignerTslOperation(),
            aggregate0,
            new PersistTslOperation(null, "tslName"));

    assertThat(aggregate1.getTslOperations()).hasSize(7);

    aggregate1.remove(BreakSignerTslOperation.class);
    assertThat(aggregate1.getTslOperations()).hasSize(5);

    aggregate1.remove(PersistTslOperation.class);
    assertThat(aggregate1.getTslOperations()).hasSize(2);

    aggregate1.remove(TslOperation.class);
    assertThat(aggregate1.getTslOperations()).isEmpty();
  }
}
