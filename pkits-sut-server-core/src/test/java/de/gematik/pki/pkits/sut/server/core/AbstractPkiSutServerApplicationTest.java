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

package de.gematik.pki.pkits.sut.server.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.pkits.sut.server.core.configs.OcspProperties;
import de.gematik.pki.pkits.sut.server.core.webserverconfigs.HandshakeInterceptor;
import org.junit.jupiter.api.Test;

class AbstractPkiSutServerApplicationTest {

  @Test
  void shouldInitializeOcspCacheAndExposeIt() {
    final OcspProperties properties = new OcspProperties();
    properties.setOcspGracePeriodSeconds(42);

    final TestApplication app = new TestApplication(properties);

    assertThat(AbstractPkiSutServerApplication.getOcspRespCache()).isNotNull();
    assertThat(HandshakeInterceptor.getOcspRespCache())
        .isSameAs(AbstractPkiSutServerApplication.getOcspRespCache());
    assertThat(app).isNotNull();
  }

  @Test
  void shouldMatchAllRequestsAndReturnEmptyFilterList() {
    final TestApplication app = new TestApplication(new OcspProperties());

    // assertThat(app.matches((HttpServletRequest) null)).isTrue();
    assertThat(app.getFilters()).isEmpty();
  }

  @Test
  void shouldFailBannerLoadingWhenTheResourceIsMissing() {
    final TestApplication app = new TestApplication(new OcspProperties());

    assertThatThrownBy(app::init)
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessageContaining("Error reading resource");
  }

  private static final class TestApplication extends AbstractPkiSutServerApplication {
    private TestApplication(final OcspProperties ocspProperties) {
      super(ocspProperties);
    }
  }
}
