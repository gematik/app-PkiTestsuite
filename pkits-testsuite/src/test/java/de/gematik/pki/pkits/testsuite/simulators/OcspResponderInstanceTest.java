/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.testsuite.simulators;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import org.junit.jupiter.api.Test;

class OcspResponderInstanceTest {

  @Test
  void testOcspResponderInstance() {
    final OcspResponderInstance ocspResponderInstance = OcspResponderInstance.getInstance();
    ocspResponderInstance.setAppPath(
        TestConfigManager.getTestSuiteConfig().getOcspResponder().getAppPath());
    assertDoesNotThrow(ocspResponderInstance::startServer);
    assertDoesNotThrow(() -> ocspResponderInstance.waitUntilWebServerIsUp(30));
    assertDoesNotThrow(ocspResponderInstance::stopServer);
  }

  @Test
  void testOcspResponderJarMissing() {
    final OcspResponderInstance ocspResp = OcspResponderInstance.getInstance();
    ocspResp.setAppPath("notValid");
    assertThatThrownBy(ocspResp::startServer)
        .isInstanceOf(PkiCommonException.class)
        .hasMessageStartingWith("Could not find jar file to start server process");
  }
}
