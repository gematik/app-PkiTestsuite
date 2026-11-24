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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URL;
import org.junit.jupiter.api.Test;

class TslProcurerPropertiesTest {

  @Test
  void shouldExposeDefaultsAndDeprecatedAlias() throws Exception {
    final TslProcurerProperties properties = new TslProcurerProperties();
    final URL url = URI.create("https://example.test/tsl.xml").toURL();

    assertThat(properties.getSource()).isEqualTo("local");
    assertThat(properties.getInitialTslDownloadUrl()).isNull();

    properties.setInitialTslDownloadUrl(url);
    assertThat(properties.getInitialTslPrimaryDownloadUrl()).isSameAs(url);

    properties.setInitialTslPrimaryDownloadUrl(url);
    assertThat(properties.getInitialTslDownloadUrl()).isSameAs(url);

    properties.setDownloadInterval(17);
    properties.setRepetitions(3);
    properties.setTslGracePeriodDays(4);
    properties.setTimeoutMilliseconds(5000);
    assertThat(properties.getDownloadInterval()).isEqualTo(17);
    assertThat(properties.getRepetitions()).isEqualTo(3);
    assertThat(properties.getTslGracePeriodDays()).isEqualTo(4);
    assertThat(properties.getTimeoutMilliseconds()).isEqualTo(5000);
  }
}
