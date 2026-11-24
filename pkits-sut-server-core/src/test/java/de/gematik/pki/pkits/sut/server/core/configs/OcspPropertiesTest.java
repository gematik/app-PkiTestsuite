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

package de.gematik.pki.pkits.sut.server.core.configs;

import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.pkits.sut.server.core.exceptions.TosException;
import java.net.URI;
import java.net.URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class OcspPropertiesTest {

  private static final String OCSP_RESPONDER_PORT_PROPERTY = "OCSP_RESPONDER_PORT";

  @AfterEach
  void tearDown() {
    System.clearProperty(OCSP_RESPONDER_PORT_PROPERTY);
  }

  @Test
  void shouldReadServiceUrlFromConfiguration() throws Exception {
    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspServiceUrl("https://example.test/ocsp");

    final URL actual = ocspProperties.readServiceUrl();

    assertThat(actual).isEqualTo(URI.create("https://example.test/ocsp").toURL());
  }

  @Test
  void shouldPreferEnvironmentUrlWhenSystemPropertyIsSet() throws Exception {
    System.setProperty(OCSP_RESPONDER_PORT_PROPERTY, "4711");
    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspServiceUrl("https://example.test/ocsp");

    final URL actual = ocspProperties.readServiceUrl();

    assertThat(actual).isEqualTo(URI.create("http://localhost:4711" + OCSP_SSP_ENDPOINT).toURL());
  }

  @Test
  void shouldThrowExceptionForMalformedConfiguredUrl() {
    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspServiceUrl("not-a-valid-url");

    assertThatThrownBy(ocspProperties::readServiceUrl)
        .isInstanceOf(TosException.class)
        .hasMessageContaining("Cannot create SSP URL");
  }

  @Test
  void shouldThrowExceptionForInvalidEnvironmentPort() {
    System.setProperty(OCSP_RESPONDER_PORT_PROPERTY, "abc");
    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspServiceUrl("https://example.test/ocsp");

    assertThatThrownBy(ocspProperties::readServiceUrl)
        .isInstanceOf(TosException.class)
        .hasMessageContaining("Cannot create SSP URL");
  }
}
