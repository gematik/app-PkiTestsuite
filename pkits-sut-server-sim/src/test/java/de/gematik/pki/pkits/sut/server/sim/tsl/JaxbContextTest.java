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

package de.gematik.pki.pkits.sut.server.sim.tsl;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_ID_LENGTH;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.Test;

class JaxbContextTest {
  private static final String TSL_FILEPATH = "TSL_default.xml";

  @Test
  void convertTsl() {
    final byte[] tslBytes =
        ResourceReader.getFileFromResourceAsBytes(TSL_FILEPATH, this.getClass());
    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);
    assertThat(tsl.getId()).hasSize(TSL_ID_LENGTH);
  }
}
