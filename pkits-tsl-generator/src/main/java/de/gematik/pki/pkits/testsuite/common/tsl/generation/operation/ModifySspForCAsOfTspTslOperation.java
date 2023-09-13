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

import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class ModifySspForCAsOfTspTslOperation implements TslOperation {

  private final String tspName;
  private final String newSsp;

  public ModifySspForCAsOfTspTslOperation(final String tspName, final String newSsp) {
    this.tspName = tspName;
    this.newSsp = newSsp;
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {
    final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();

    TslModifier.modifySspForCAsOfTsp(tslUnsigned, tspName, newSsp);

    return new TslContainer(tslUnsigned);
  }
}
