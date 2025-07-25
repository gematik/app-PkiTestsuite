/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.sut.server.sim.configs;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.pkits.sut.server.sim.webserverconfigs.HandshakeInterceptor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class HandshakeInterceptorTest {

  @Test
  void configNotNull() {
    assertThat(HandshakeInterceptor.getHandshakeConfig()).isNotNull();
  }

  @Test
  void isEnabled() {
    assertThat(HandshakeInterceptor.getHandshakeConfig().isEnabled()).isTrue();
  }

  @Test
  void hasTslProcurer() {
    assertThat(HandshakeInterceptor.getTslProcurer()).isNotNull();
  }
}
