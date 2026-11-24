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
import static org.assertj.core.api.Assertions.assertThatCode;

import de.gematik.pki.pkits.sut.server.core.configs.HandshakeInterceptorConfig;
import de.gematik.pki.pkits.sut.server.core.configs.OcspProperties;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class HandshakeInterceptorCoreTest {

  @Test
  void shouldSetAndGetStaticConfiguration() {
    final HandshakeInterceptorConfig config = new HandshakeInterceptorConfig();
    config.setEnabled(true);

    HandshakeInterceptor.setStaticHandshakeConfig(config);
    HandshakeInterceptor.setStaticOcspRespCache(null);

    assertThat(HandshakeInterceptor.getHandshakeConfig()).isSameAs(config);
    assertThat(HandshakeInterceptor.getOcspRespCache()).isNull();
  }

  @Test
  void shouldSkipClientTrustValidationWhenDisabled() {
    final HandshakeInterceptorConfig config = new HandshakeInterceptorConfig();
    config.setEnabled(false);
    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspEnabled(false);

    final HandshakeInterceptor interceptor = new HandshakeInterceptor();
    HandshakeInterceptor.setStaticHandshakeConfig(config);
    HandshakeInterceptor.setStaticOcspProperties(ocspProperties);

    assertThatCode(() -> interceptor.checkClientTrusted(new X509Certificate[0], "RSA"))
        .doesNotThrowAnyException();
  }

  @Test
  void shouldAllowServerTrustValidationAndReturnNoAcceptedIssuers() {
    final HandshakeInterceptor interceptor = new HandshakeInterceptor();
    assertThatCode(() -> interceptor.checkServerTrusted(new X509Certificate[0], "RSA"))
        .doesNotThrowAnyException();
    assertThat(interceptor.getAcceptedIssuers()).isEmpty();
  }
}
