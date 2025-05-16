/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.common.tsl.generation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslContainerTest {

  @Test
  void testRSATslContainerFromTsl() {
    final TrustStatusListType tsl = TslReader.getTslUnsigned(CreateTslTemplate.ARVATO_TU_TSL);

    final TslContainer tslContainer = new TslContainer(tsl);
    assertThat(tslContainer.getAsTslUnsignedBytes()).hasSizeGreaterThan(0);
    assertThat(tslContainer.getAsTslUnsignedDoc()).isNotNull();

    // same reference
    assertThat(tslContainer.getAsTslUnsigned()).isEqualTo(tsl);

    assertDoesNotThrow(() -> new TslContainer(tslContainer));
  }

  @Test
  void testECCTslContainerFromTsl() {
    final TrustStatusListType tsl =
        TslReader.getTslUnsigned(CreateTslTemplate.ARVATO_TU_ECC_ONLY_TSL);

    final TslContainer tslContainer = new TslContainer(tsl);
    assertThat(tslContainer.getAsTslUnsignedBytes()).hasSizeGreaterThan(0);
    assertThat(tslContainer.getAsTslUnsignedDoc()).isNotNull();

    // same reference
    assertThat(tslContainer.getAsTslUnsigned()).isEqualTo(tsl);

    assertDoesNotThrow(() -> new TslContainer(tslContainer));
  }

  @Test
  void testRSATslContainerFromDocument() {

    final Document tslDoc = TslReader.getTslAsDoc(CreateTslTemplate.ARVATO_TU_TSL);

    final TslContainer tslContainer = new TslContainer(tslDoc);
    assertThat(tslContainer.getAsTslUnsignedBytes()).hasSizeGreaterThan(0);
    assertThat(tslContainer.getAsTslUnsigned()).isNotNull();

    // same reference
    assertThat(tslContainer.getAsTslUnsignedDoc()).isEqualTo(tslDoc);
  }

  @Test
  void testECCTslContainerFromDocument() {

    final Document tslDoc = TslReader.getTslAsDoc(CreateTslTemplate.ARVATO_TU_ECC_ONLY_TSL);

    final TslContainer tslContainer = new TslContainer(tslDoc);
    assertThat(tslContainer.getAsTslUnsignedBytes()).hasSizeGreaterThan(0);
    assertThat(tslContainer.getAsTslUnsigned()).isNotNull();

    // same reference
    assertThat(tslContainer.getAsTslUnsignedDoc()).isEqualTo(tslDoc);
  }

  @Test
  void testTslContainerFromBadBytes() {

    final byte[] tslBadBytes = new byte[] {0, 1, 2};

    final TslContainer tslContainer = new TslContainer(tslBadBytes);

    assertThatThrownBy(tslContainer::getAsTslUnsigned)
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(TslConverter.ERROR_READING_TSL);

    assertThatThrownBy(tslContainer::getAsTslUnsignedDoc)
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(TslConverter.ERROR_READING_TSL);

    // same reference
    assertThat(tslContainer.getAsTslUnsignedBytes()).isEqualTo(tslBadBytes);
  }
}
