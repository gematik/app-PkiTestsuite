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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class TlsClientApplication {
  public static void main(final String[] args) {

    log.info("TLS args: {}", StringUtils.joinWith(" | ", (Object[]) args));

    final InetAddress serverAddress;
    final int serverPort = Integer.parseUnsignedInt(args[1]);
    final Path certPath = Path.of(args[2]);
    final String clientKeystorePassw = args[3];

    try {
      serverAddress = InetAddress.getByName(args[0]);
      final TlsConnection connection =
          TlsConnection.builder()
              .clientKeystorePassw(clientKeystorePassw)
              .serverAddress(serverAddress)
              .sutServerPort(serverPort)
              .tlsSettings(PluginConfig.getInstance().getTlsSettings())
              .build();

      log.info("TLS connection: start");
      connection.tlsConnectCerts(certPath);

    } catch (final TlsClientException e) {
      log.info("No ssl connection established.");
      System.exit(1);
      return;
    } catch (final UnknownHostException e) {
      log.info("Host unknown: {}", args[0]);
      System.exit(2);
      return;
    } catch (final UnrecoverableKeyException e) {
      log.info("Error with certificate key: {}", certPath);
      System.exit(2);
      return;
    } catch (final CertificateException e) {
      log.info("Error with certificate: {}", certPath);
      System.exit(2);
      return;
    } catch (final NoSuchAlgorithmException e) {
      log.info("Algorithm problem in cert: {}", certPath);
      System.exit(2);
      return;
    } catch (final IOException | KeyStoreException | KeyManagementException e) {
      System.exit(2);
      return;
    }
    log.info("TLS connected.");
  }
}
