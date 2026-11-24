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

package de.gematik.pki.pkits.sut.server.core.webserverconfigs;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.test.util.ReflectionTestUtils;

class TomcatServletCustomizerTest {

  @Test
  void shouldRegisterConnectorCustomizerWhenSslIsEnabled() {
    final TomcatServletCustomizer customizer = new TomcatServletCustomizer();
    ReflectionTestUtils.setField(customizer, "sslenabled", true);
    ReflectionTestUtils.setField(customizer, "sslprotocol", "TLS");
    ReflectionTestUtils.setField(customizer, "sslciphers", "TLS_AES_256_GCM_SHA384");
    final TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();

    customizer.customize(factory);

    assertThat(factory.getConnectorCustomizers()).hasSize(1);
  }

  @Test
  void shouldSkipConnectorCustomizerWhenSslIsDisabled() {
    final TomcatServletCustomizer customizer = new TomcatServletCustomizer();
    ReflectionTestUtils.setField(customizer, "sslenabled", false);
    ReflectionTestUtils.setField(customizer, "sslprotocol", "TLS");
    ReflectionTestUtils.setField(customizer, "sslciphers", "TLS_AES_256_GCM_SHA384");
    final TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();

    customizer.customize(factory);

    assertThat(factory.getConnectorCustomizers()).isEmpty();
  }
}
