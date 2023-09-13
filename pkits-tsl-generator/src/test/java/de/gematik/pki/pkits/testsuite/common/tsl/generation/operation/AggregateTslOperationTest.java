/*
 * Copyright 2023 gematik GmbH
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

import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import java.util.function.Function;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

class AggregateTslOperationTest {

  @Test
  void testChained() {

    final AggregateTslOperation aggregate0 =
        AggregateTslOperation.builder()
            .chained(new DeleteTspServiceForCertShaTslOperation("referenceSha256"))
            .chained(new ChangNameTslOperation("dummy1"))
            .chained(new BreakSignerTslOperation())
            .build();

    final AggregateTslOperation aggregate1 =
        AggregateTslOperation.builder()
            .chained(new DeleteTspServiceForCertShaTslOperation("referenceSha256"))
            .chained(new ChangNameTslOperation("dummy2"))
            .chained(new BreakSignerTslOperation())
            .chained(aggregate0)
            .chained(new DeleteTspServiceForCertShaTslOperation("referenceSha256"))
            .build();

    assertThat(aggregate1.getTslOperations()).hasSize(7);

    aggregate1.remove(BreakSignerTslOperation.class);
    assertThat(aggregate1.getTslOperations()).hasSize(5);

    aggregate1.remove(DeleteTspServiceForCertShaTslOperation.class);
    assertThat(aggregate1.getTslOperations()).hasSize(2);

    aggregate1.remove(TslOperation.class);
    assertThat(aggregate1.getTslOperations()).isEmpty();
  }

  @Test
  void testRemove() {

    final AggregateTslOperation aggregate0 =
        new AggregateTslOperation(
            new DeleteTspServiceForCertShaTslOperation("referenceSha256"),
            new ChangNameTslOperation("dummy1"),
            new BreakSignerTslOperation());

    final AggregateTslOperation aggregate1 =
        new AggregateTslOperation(
            new DeleteTspServiceForCertShaTslOperation("referenceSha256"),
            new ChangNameTslOperation("dummy2"),
            new BreakSignerTslOperation(),
            aggregate0,
            new DeleteTspServiceForCertShaTslOperation("referenceSha256"));

    assertThat(aggregate1.getTslOperations()).hasSize(7);

    aggregate1.remove(BreakSignerTslOperation.class);
    assertThat(aggregate1.getTslOperations()).hasSize(5);

    aggregate1.remove(DeleteTspServiceForCertShaTslOperation.class);
    assertThat(aggregate1.getTslOperations()).hasSize(2);

    aggregate1.remove(TslOperation.class);
    assertThat(aggregate1.getTslOperations()).isEmpty();
  }

  @Test
  void testAggregateApply() {

    final Function<Integer, TslOperation> tslOperationFunc =
        (power) ->
            tslContainer -> {
              final byte elem = (byte) (Math.pow(2, power));
              final byte[] updatedBytes =
                  ArrayUtils.add(tslContainer.getAsTslUnsignedBytes(), elem);
              return new TslContainer(updatedBytes);
            };

    final AggregateTslOperation tslOperation1 =
        AggregateTslOperation.builder()
            .chained(tslOperationFunc.apply(0))
            .chained(tslOperationFunc.apply(1))
            .build();

    final TslOperation tslOperation2 = tslOperationFunc.apply(2);

    final AggregateTslOperation tslOperation3 =
        new AggregateTslOperation(tslOperationFunc.apply(3), tslOperationFunc.apply(4));

    final TslOperation tslOperation4 = tslOperationFunc.apply(0);

    final TslOperation aggregateTslOperation =
        AggregateTslOperation.builder()
            .chained(tslOperation1)
            .chained(tslOperation2)
            .chained(tslOperation3)
            .chained(tslOperation4)
            .build();

    final byte[] initialBytes = {-99};
    final byte[] expectedBytes = {-99, 1, 2, 4, 8, 16, 1};
    final TslContainer tslContainer = aggregateTslOperation.apply(initialBytes);
    assertThat(tslContainer.getAsTslUnsignedBytes()).isEqualTo(expectedBytes);
  }
}
