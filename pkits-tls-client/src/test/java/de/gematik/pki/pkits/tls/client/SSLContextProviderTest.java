/*
 * Copyright (c) 2023 gematik GmbH
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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class SSLContextProviderTest {

  static final TlsSettings TLS_SETTINGS = PluginConfig.getInstance().getTlsSettings();

  @Test
  void createSSLContext() {
    final Path clientKeystorePath =
        Path.of("../testDataTemplates/certificates/rsa/valid/ee_default.p12");

    final SSLContext sslContext =
        new SSLContextProvider().createSSLContext(clientKeystorePath, "00");

    Assertions.assertThat(sslContext).isNotNull();
  }

  @Disabled("Development only")
  @Test
  void connectRsa() throws URISyntaxException, UnknownHostException {
    final String certResourcePath = "../testDataTemplates/certificates/rsa/valid/ee_default.p12";
    final Path clientKeystorePath =
        Path.of(
            Objects.requireNonNull(
                    getClass().getClassLoader().getResource(certResourcePath),
                    "Resource Path: " + certResourcePath + " in configuration does not exist.")
                .toURI());

    final TlsConnection connection =
        TlsConnection.builder()
            .clientKeystorePassw("00")
            .serverAddress(InetAddress.getByName("127.0.0.1"))
            .sutServerPort(8443)
            .tlsSettings(TLS_SETTINGS)
            .build();

    assertDoesNotThrow(
        () -> connection.tlsConnectCerts(clientKeystorePath),
        String.format("Exception with cert: " + clientKeystorePath));
  }

  @Disabled("Development only")
  @Test
  void connectEcc() throws URISyntaxException, UnknownHostException {
    final String certResourcePath =
        "../testDataTemplates/certificates/ecc/fachmodul_clientCerts/valid/ee_default.p12";
    final Path clientKeystorePath =
        Path.of(
            Objects.requireNonNull(
                    getClass().getClassLoader().getResource(certResourcePath),
                    "Resource Path: " + certResourcePath + " in configuration does not exist.")
                .toURI());

    final TlsConnection connection =
        TlsConnection.builder()
            .clientKeystorePassw("00")
            .serverAddress(InetAddress.getByName("127.0.0.1"))
            .sutServerPort(8443)
            .tlsSettings(TLS_SETTINGS)
            .build();

    assertDoesNotThrow(
        () -> connection.tlsConnectCerts(clientKeystorePath),
        String.format("Exception with cert: " + clientKeystorePath));
  }
}
