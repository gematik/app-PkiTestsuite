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

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ChangNameTslOperationTest {

  @Test
  void testRSAChangNameTslOperation() {
    final TrustStatusListType tsl = CreateTslTemplate.defaultTsl(false);
    final String tslStrUnsigned =
        new String(TslConverter.tslUnsignedToBytes(tsl), StandardCharsets.UTF_8);

    final String substrFormat =
        "<TSPInformation><TSPName><Name xml:lang=\"DE\">%s</Name></TSPName><TSPTradeName>"
            + "<Name xml:lang=\"DE\">%s</Name></TSPTradeName>";

    final String originalSubstr =
        substrFormat.formatted(
            PkitsConstants.GEMATIK_TEST_TSP, PkitsConstants.GEMATIK_TEST_TSP_TRADENAME);
    final String newTspTradeName = "gematik Test-TSL: NewSampleTslName";
    final String newSubstr =
        substrFormat.formatted(PkitsConstants.GEMATIK_TEST_TSP, newTspTradeName);

    assertThat(tslStrUnsigned).containsOnlyOnce(originalSubstr).doesNotContain(newSubstr);

    final TslOperation tslOperation = new ChangNameTslOperation(newTspTradeName);
    final TslContainer tslContainer = tslOperation.apply(tsl);

    final String newTslStr =
        new String(tslContainer.getAsTslUnsignedBytes(), StandardCharsets.UTF_8);

    assertThat(newTslStr).doesNotContain(originalSubstr).containsOnlyOnce(newSubstr);
  }

  @Test
  void testECCChangNameTslOperation() {
    final TrustStatusListType tsl = CreateTslTemplate.defaultTsl(true);
    final String tslStrUnsigned =
        new String(TslConverter.tslUnsignedToBytes(tsl), StandardCharsets.UTF_8);

    final String substrFormat =
        "<TSPInformation><TSPName><Name xml:lang=\"DE\">%s</Name></TSPName><TSPTradeName>"
            + "<Name xml:lang=\"DE\">%s</Name></TSPTradeName>";

    final String originalSubstr =
        substrFormat.formatted(
            PkitsConstants.GEMATIK_TEST_TSP, PkitsConstants.GEMATIK_TEST_TSP_TRADENAME);
    final String newTspTradeName = "gematik Test-TSL: NewSampleTslName";
    final String newSubstr =
        substrFormat.formatted(PkitsConstants.GEMATIK_TEST_TSP, newTspTradeName);

    assertThat(tslStrUnsigned).containsOnlyOnce(originalSubstr).doesNotContain(newSubstr);

    final TslOperation tslOperation = new ChangNameTslOperation(newTspTradeName);
    final TslContainer tslContainer = tslOperation.apply(tsl);

    final String newTslStr =
        new String(tslContainer.getAsTslUnsignedBytes(), StandardCharsets.UTF_8);

    assertThat(newTslStr).doesNotContain(originalSubstr).containsOnlyOnce(newSubstr);
  }
}
