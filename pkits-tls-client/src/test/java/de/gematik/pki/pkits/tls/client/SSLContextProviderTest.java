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

package de.gematik.pki.pkits.tls.client;

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.KEYSTORE_PASSWORD;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.utils.ResourceReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class SSLContextProviderTest {

  static final TlsSettings TLS_SETTINGS = PluginConfig.getInstance().getTlsSettings();

  final Path clientKeystorePath =
      ResourceReader.getFilePathFromResources("certificates/rsa/valid/ee_default.p12", getClass());

  @Test
  void createSSLContext() {

    final SSLContext sslContext =
        new SSLContextProvider().createSSLContext(clientKeystorePath, KEYSTORE_PASSWORD);

    Assertions.assertThat(sslContext).isNotNull();
  }

  @Disabled("Development only")
  @Test
  void connectRsa() throws UnknownHostException {

    final TlsConnection connection =
        TlsConnection.builder()
            .clientKeystorePassw(KEYSTORE_PASSWORD)
            .serverAddress(InetAddress.getByName("127.0.0.1"))
            .sutServerPort(8443)
            .tlsSettings(TLS_SETTINGS)
            .build();

    assertDoesNotThrow(
        () -> connection.tlsConnectCerts(clientKeystorePath),
        String.format("Exception with cert: %s", clientKeystorePath));
  }

  @Disabled("Development only")
  @Test
  void connectEcc() throws UnknownHostException {
    final Path clientKeystorePath =
        ResourceReader.getFilePathFromResources(
            "certificates/ecc/valid/ee_default.p12", getClass());

    final TlsConnection connection =
        TlsConnection.builder()
            .clientKeystorePassw(KEYSTORE_PASSWORD)
            .serverAddress(InetAddress.getByName("127.0.0.1"))
            .sutServerPort(8443)
            .tlsSettings(TLS_SETTINGS)
            .build();

    assertDoesNotThrow(
        () -> connection.tlsConnectCerts(clientKeystorePath),
        String.format("Exception with cert: %s", clientKeystorePath));
  }
}
