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

import de.gematik.pki.pkits.sut.server.core.tsl.DefaultTslSource;
import de.gematik.pki.pkits.sut.server.core.tsl.TslProcurer;
import de.gematik.pki.pkits.sut.server.core.tsl.TslSource;
import java.net.URI;
import org.junit.jupiter.api.Test;

class TslProcurerConfigurationTest {

  @Test
  void shouldCreateTslProcurerBeanFromConfiguration() throws Exception {
    final TslProcurerConfiguration configuration = new TslProcurerConfiguration();

    final TslProcurerProperties tslProcurerProperties = new TslProcurerProperties();
    tslProcurerProperties.setSource("local");
    tslProcurerProperties.setInitialTslDownloadUrl(
        URI.create("http://example.test/tsl.xml").toURL());
    tslProcurerProperties.setDownloadInterval(1);
    tslProcurerProperties.setRepetitions(3);
    tslProcurerProperties.setTslGracePeriodDays(0);
    tslProcurerProperties.setTimeoutMilliseconds(100);

    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspGracePeriodSeconds(30);

    final TslSource tslSource = new DefaultTslSource(tslProcurerProperties);

    final TslProcurer tslProcurer =
        configuration.tslProcurer(tslProcurerProperties, ocspProperties, tslSource);

    assertThat(tslProcurer).isNotNull();
    assertThat(tslProcurer.getClass()).isEqualTo(TslProcurer.class);
  }
}
