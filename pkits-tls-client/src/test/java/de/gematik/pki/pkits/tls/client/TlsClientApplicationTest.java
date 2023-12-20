/*
 * Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.tls.client;

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.KEYSTORE_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.utils.ResourceReader;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class TlsClientApplicationTest {

  private static Path clientKeystorePath;

  @BeforeAll
  static void setUp() {
    clientKeystorePath =
        ResourceReader.getFilePathFromResources(
            "certificates/rsa/valid/ee_default.p12", TlsClientApplicationTest.class);
  }

  @Test
  void verifyMain() {
    assertThat(
            TlsClientApplication.mainWrapper(
                new String[] {
                  "unknown",
                  String.valueOf(8443),
                  String.valueOf(clientKeystorePath),
                  KEYSTORE_PASSWORD,
                  String.valueOf(0)
                }))
        .isEqualTo(2);
  }

  @Test
  void verifyNoServerAvailable() {
    final int exitCode =
        TlsClientApplication.connectTls(
            "localhost", 8443, clientKeystorePath, KEYSTORE_PASSWORD, 0);
    assertThat(exitCode).isEqualTo(2);
  }

  @Test
  void verifyServerUnknownAvailable() {
    final int exitCode =
        TlsClientApplication.connectTls("unknown", 8443, clientKeystorePath, KEYSTORE_PASSWORD, 0);
    assertThat(exitCode).isEqualTo(2);
  }

  @Test
  void verifyBadClientCert() {
    final Path badCert =
        ResourceReader.getFilePathFromResources(
            "certificates/empty.p12", TlsClientApplicationTest.class);
    final int exitCode =
        TlsClientApplication.connectTls("localhost", 8443, badCert, KEYSTORE_PASSWORD, 0);
    assertThat(exitCode).isEqualTo(2);
  }

  @Test
  void verifyWrongAlgo() {
    final Path wrongAlgoCert =
        ResourceReader.getFilePathFromResources(
            "certificates/dsaCert.p12", TlsClientApplicationTest.class);
    final int exitCode =
        TlsClientApplication.connectTls("localhost", 8443, wrongAlgoCert, KEYSTORE_PASSWORD, 0);
    assertThat(exitCode).isEqualTo(2);
  }

  @Test
  void verifyWrongPassw() {
    final int exitCode =
        TlsClientApplication.connectTls("localhost", 8443, clientKeystorePath, "01", 0);
    assertThat(exitCode).isEqualTo(2);
  }
}
