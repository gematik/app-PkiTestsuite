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
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor
public class ChangNameTslOperation implements TslOperation {
  private String newTspTradeName;

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();

    TslModifier.modifyTspTradeName(
        tslUnsigned,
        PkitsConstants.GEMATIK_TEST_TSP,
        PkitsConstants.GEMATIK_TEST_TSP_TRADENAME,
        newTspTradeName);

    return new TslContainer(tslUnsigned);
  }
}
