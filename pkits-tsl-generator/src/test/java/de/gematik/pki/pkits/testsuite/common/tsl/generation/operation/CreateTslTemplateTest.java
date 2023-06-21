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
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.AVARTO_TSL_CERT_TSL_CA28_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.AVARTO_TSL_OCSP_SIGNER_10_CERT_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.AVARTO_TSL_OCSP_SIGNER_8_CERT_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.deleteInitialTspServices;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CreateTslTemplateTest {
  private TslContainer tslContainer = null;

  @BeforeEach
  void setUp() {
    tslContainer = new TslContainer(TslReader.getTsl(ARVATO_TU_TSL));
  }

  @Test
  void verifyDeleteInitialTspServices() {

    final int oldTslBytes = tslContainer.getAsTslBytes().length;
    final int newTslBytes = deleteInitialTspServices(tslContainer).getAsTslBytes().length;
    assertThat(newTslBytes).isLessThan(oldTslBytes);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        AVARTO_TSL_CERT_TSL_CA28_SHA256,
        AVARTO_TSL_OCSP_SIGNER_8_CERT_SHA256,
        AVARTO_TSL_OCSP_SIGNER_10_CERT_SHA256
      })
  void verifyToRemoveCertExists(final String certhash) {
    assertThat(new DeleteTspServiceForCertShaTslOperation(certhash).count(tslContainer))
        .isEqualTo(1);
  }
}
