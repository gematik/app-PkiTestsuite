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

import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TU_TSL;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslOperationTest {

  TrustStatusListType tsl;
  Document tslDoc;
  byte[] tslBytes;

  @BeforeEach
  void init() {
    tsl = TslReader.getTsl(ARVATO_TU_TSL);
    tslDoc = TslReader.getTslAsDoc(ARVATO_TU_TSL);
    tslBytes = GemLibPkiUtils.readContent(ARVATO_TU_TSL);
  }

  @Test
  void testApply() {
    final TslOperation tslOperation = tslContainer -> tslContainer;

    final TslContainer tc1 = tslOperation.apply(tsl);
    assertThat(TslGenerationTestUtils.documentsAreEqual(tc1.getAsTslDoc(), tslDoc)).isTrue();

    final TslContainer tc2 = tslOperation.apply(tslDoc);
    assertThat(TslGenerationTestUtils.documentsAreEqual(tc2.getAsTslDoc(), tslDoc)).isTrue();

    final TslContainer tc3 = tslOperation.apply(tslBytes);
    assertThat(Arrays.equals(tc3.getAsTslBytes(), tslBytes)).isTrue();
  }
}
