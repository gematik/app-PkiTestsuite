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
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.charset.StandardCharsets;

public class ModifyEmailTslOperation implements TslOperation {

  private String getFirstSchemeOperatorMailAddressOfTsl(final TrustStatusListType tsl) {
    return tsl.getSchemeInformation()
        .getSchemeOperatorAddress()
        .getElectronicAddress()
        .getURI()
        .get(0)
        .getValue();
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    final TrustStatusListType tsl = tslContainer.getAsTsl();
    final byte[] tslBytes = tslContainer.getAsTslBytes();

    // break integrity of TSL and verify signature again
    final String emailToStrOld = getFirstSchemeOperatorMailAddressOfTsl(tsl);
    final String emailToStrNew = "mailto:signatureInvalid@gematik.de";
    final String tslStr = new String(tslBytes, StandardCharsets.UTF_8);
    final byte[] brokenTsl =
        tslStr.replace(emailToStrOld, emailToStrNew).getBytes(StandardCharsets.UTF_8);

    return new TslContainer(brokenTsl);
  }
}
