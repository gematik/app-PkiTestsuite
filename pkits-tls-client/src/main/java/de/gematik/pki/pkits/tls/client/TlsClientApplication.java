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

  public static int connectTls(
      final String ipAddressOrFqdn, final int port, final Path certPath, final String password) {
    try {

      final InetAddress serverAddress = InetAddress.getByName(ipAddressOrFqdn);

      final TlsConnection connection =
          TlsConnection.builder()
              .serverAddress(serverAddress)
              .sutServerPort(port)
              .clientKeystorePassw(password)
              .tlsSettings(PluginConfig.getInstance().getTlsSettings())
              .build();

      log.info("TLS connection: start");
      connection.tlsConnectCerts(certPath);
      log.info("TLS connected.");

    } catch (final TlsClientException e) {
      log.info("No ssl connection established.");
      return 1;
    } catch (final UnknownHostException e) {
      log.info("Host unknown: {}", ipAddressOrFqdn);
      return 2;
    } catch (final UnrecoverableKeyException e) {
      log.info("Error with certificate key: {}", certPath);
      return 2;
    } catch (final CertificateException e) {
      log.info("Error with certificate: {}", certPath);
      return 2;
    } catch (final NoSuchAlgorithmException e) {
      log.error("Algorithm problem in cert:" + certPath, e);
      return 2;
    } catch (final IOException | KeyStoreException | KeyManagementException e) {
      return 2;
    }

    return 0;
  }

  public static void main(final String[] args) {

    log.info("TLS args: {}", StringUtils.joinWith(" | ", (Object[]) args));

    final String ipAddressOrFqdn = args[0];
    final int serverPort = Integer.parseUnsignedInt(args[1]);
    final Path certPath = Path.of(args[2]);
    final String clientKeystorePassw = args[3];

    final int returnCode = connectTls(ipAddressOrFqdn, serverPort, certPath, clientKeystorePassw);

    System.exit(returnCode);
  }
}
