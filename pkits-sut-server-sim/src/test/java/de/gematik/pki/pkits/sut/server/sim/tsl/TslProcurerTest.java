/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.sut.server.sim.tsl;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.pkits.sut.server.sim.configs.OcspConfig;
import de.gematik.pki.pkits.sut.server.sim.configs.TslProcurerConfig;
import de.gematik.pki.pkits.sut.server.sim.exceptions.TosException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.stereotype.Service;

@SpringBootTest
@Service
class TslProcurerTest {

  @Autowired private TslProcurerConfig tslProcurerConfig;
  @Autowired private OcspConfig ocspConfig;

  /* NOTE: we do not test this extensively at the moment.
   To do so, for example, implement TSL Download Server Mock, change test to "not throwing", .hasSize(n)...
  */
  @Test
  void getTslInfoProv() {
    final TslProcurer tslProcurer = new TslProcurer(tslProcurerConfig, ocspConfig);
    assertThatThrownBy(tslProcurer::getTslInfoProv)
        .isInstanceOf(TosException.class)
        .hasMessageContaining("(yet)");
  }
}
