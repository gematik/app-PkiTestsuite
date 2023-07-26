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

import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.Getter;

public class AggregateTslOperation implements TslOperation {

  public static AggregateTslOperationBuilder builder() {
    return new AggregateTslOperationBuilder();
  }

  public static class AggregateTslOperationBuilder {

    private final AggregateTslOperation aggregateTslOperation = new AggregateTslOperation();

    public AggregateTslOperationBuilder chained(final TslOperation tslOperation) {
      aggregateTslOperation.add(tslOperation);
      return this;
    }

    public AggregateTslOperation build() {
      return aggregateTslOperation;
    }
  }

  @Getter private final List<TslOperation> tslOperations = new ArrayList<>();

  public AggregateTslOperation(final List<TslOperation> tslOperations) {
    tslOperations.forEach(this::add);
  }

  public AggregateTslOperation(final TslOperation... tslOperations) {
    this(Arrays.asList(tslOperations));
  }

  protected void add(final TslOperation tslOperation) {
    if (tslOperation instanceof final AggregateTslOperation aggregateTslOperation) {
      this.tslOperations.addAll(aggregateTslOperation.tslOperations);
    } else {
      this.tslOperations.add(tslOperation);
    }
  }

  protected void remove(final Class<? extends TslOperation> clazz) {
    this.tslOperations.removeIf(clazz::isInstance);
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    TslContainer currentTslContainer = new TslContainer(tslContainer);

    for (final TslOperation tslOperation : tslOperations) {
      currentTslContainer = tslOperation.apply(currentTslContainer);
    }
    return currentTslContainer;
  }
}
