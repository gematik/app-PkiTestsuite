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

import static de.gematik.pki.pkits.sut.server.core.configs.TslConfig.buildTslDownloadUrl;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.MalformedURLException;
import java.net.URI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TslConfigTest {

  @AfterEach
  void tearDown() {
    System.clearProperty("TSL_PROVIDER_PORT");
  }

  @Test
  void shouldKeepOriginalUrlWhenNoTslProviderPortIsConfigured() throws MalformedURLException {
    System.clearProperty("TSL_PROVIDER_PORT");

    final String originalUrl = "http://example.test/tsl/tsl.xml?activeTslSeqNr=0";

    assertThat(buildTslDownloadUrl(URI.create(originalUrl).toURL())).isEqualTo(originalUrl);
  }

  @Test
  void shouldReplacePortWhenTslProviderPortIsConfigured() throws MalformedURLException {
    System.setProperty("TSL_PROVIDER_PORT", "4711");

    final String originalUrl = "http://example.test/tsl/tsl.xml?activeTslSeqNr=0";
    final String expectedUrl = "http://example.test:4711/tsl/tsl.xml?activeTslSeqNr=0";

    assertThat(buildTslDownloadUrl(URI.create(originalUrl).toURL())).isEqualTo(expectedUrl);
  }
}
