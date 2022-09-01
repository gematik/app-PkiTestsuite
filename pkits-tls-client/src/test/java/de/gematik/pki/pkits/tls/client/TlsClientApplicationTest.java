/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.pkits.tls.client;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import com.ginsberg.junit.exit.SystemExitPreventedException;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class TlsClientApplicationTest {

  private static String clientKeystorePath;

  @BeforeAll
  static void setUp() {
    clientKeystorePath =
        Path.of("../testDataTemplates/certificates/rsa/valid/ee_default.p12").toString();
  }

  @Test
  @ExpectSystemExitWithStatus(2)
  void verifyMainNoServerAvailable() {

    assertThatThrownBy(
            () ->
                TlsClientApplication.main(
                    new String[] {"unknown", "8443", clientKeystorePath, "00"}))
        .isInstanceOf(SystemExitPreventedException.class)
        .hasMessage(null);
  }

  @Test
  @ExpectSystemExitWithStatus(1)
  void verifyMainWithoutOcsp() {

    assertThatThrownBy(
            () ->
                TlsClientApplication.main(
                    new String[] {"localhost", "8443", clientKeystorePath, "00"}))
        .isInstanceOf(SystemExitPreventedException.class)
        .hasMessage(null);
  }
}
