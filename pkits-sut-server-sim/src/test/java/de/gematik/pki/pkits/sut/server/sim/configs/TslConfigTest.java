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

package de.gematik.pki.pkits.sut.server.sim.configs;

import static de.gematik.pki.pkits.sut.server.sim.configs.TslConfig.buildTslDownloadUrl;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.MalformedURLException;
import java.net.URL;
import org.junit.jupiter.api.Test;

class TslConfigTest {

  @Test
  void verifyBuildTslDownloadUrl() throws MalformedURLException {
    System.clearProperty("TSL_PROVIDER_PORT");
    final String str = "http://das/ist/ein/test.xml";
    assertThat(buildTslDownloadUrl(new URL(str))).isEqualTo(str);
  }

  @Test
  void verifyBuildTslDownloadUrlFromProp() throws MalformedURLException {
    final int port = 666;
    System.setProperty("TSL_PROVIDER_PORT", String.valueOf(port));
    final String inStr = "http://das/ist/ein/test.xml?blub=bla";
    final String outStr = "http://das:" + port + "/ist/ein/test.xml?blub=bla";
    assertThat(buildTslDownloadUrl(new URL(inStr))).isEqualTo(outStr);
  }
}
