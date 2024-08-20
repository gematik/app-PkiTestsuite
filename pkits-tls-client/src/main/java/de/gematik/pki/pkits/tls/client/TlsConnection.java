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

import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.TlsFatalAlertReceived;

@Builder
@Slf4j
public class TlsConnection {

  private final String clientKeystorePassw;
  private final InetAddress serverAddress;
  private final int sutServerPort;
  private final TlsSettings tlsSettings;
  private final int ocspDelaySeconds;

  static {
    Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
  }

  public void tlsConnectCerts(final Path certPath)
      throws IOException,
          UnrecoverableKeyException,
          CertificateException,
          NoSuchAlgorithmException,
          KeyStoreException,
          KeyManagementException,
          TlsClientException,
          TlsConnectionException {
    tlsConnect(certPath, clientKeystorePassw, serverAddress, sutServerPort);
  }

  private void tlsConnect(
      final Path clientKeystorePath,
      final String clientKeystorePassw,
      final InetAddress serverAddress,
      final int serverPort)
      throws NoSuchAlgorithmException,
          KeyStoreException,
          IOException,
          CertificateException,
          UnrecoverableKeyException,
          KeyManagementException,
          TlsClientException,
          TlsConnectionException {

    System.setProperty(
        "jdk.tls.namedGroups",
        "brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp256r1, secp384r1");

    final P12Container p12Container;
    try {
      p12Container = P12Reader.getContentFromP12(clientKeystorePath, clientKeystorePassw);
    } catch (final Exception e) {
      throw new TlsClientException("Cannot read certificate: " + clientKeystorePath);
    }
    if (p12Container == null) {
      throw new TlsClientException("Cannot read certificate: " + clientKeystorePath);
    }
    final String algorithm = p12Container.getCertificate().getPublicKey().getAlgorithm();

    final String kfAlgorithm;
    final String[] ciphersSuites;
    if ("EC".equalsIgnoreCase(algorithm)) {
      ciphersSuites = tlsSettings.getEcCiphersSuites();
      kfAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

    } else if ("RSA".equalsIgnoreCase(algorithm)) {
      ciphersSuites = tlsSettings.getRsaCiphersSuites();
      kfAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
    } else {
      throw new TlsClientException("Algorithm %s is not supported.".formatted(algorithm));
    }
    final KeyManagerFactory kmf = KeyManagerFactory.getInstance(kfAlgorithm);
    final KeyStore ks = KeyStore.getInstance("PKCS12");

    final InputStream keystoreIs = Files.newInputStream(clientKeystorePath);
    ks.load(keystoreIs, clientKeystorePassw.toCharArray());
    keystoreIs.close();

    kmf.init(ks, clientKeystorePassw.toCharArray());

    final SSLContext sslContextClient =
        new SSLContextProvider().createSSLContext(clientKeystorePath, clientKeystorePassw);

    sslContextClient.init(kmf.getKeyManagers(), new TrustManager[] {new BlindTrustManager()}, null);

    log.info("algorithm: {}, ciphersSuites: {}", algorithm, Arrays.asList(ciphersSuites));

    log.info("Try to connect with cert \"{}\"", clientKeystorePath);
    try (final SSLSocket clientSSLSocket =
        (SSLSocket) sslContextClient.getSocketFactory().createSocket()) {
      // Attempt to establish the connection
      sslConnect(serverAddress, serverPort, clientSSLSocket, ciphersSuites);
      // Start the handshake
      sslHandshake(clientSSLSocket);
    } catch (final IOException e) {
      log.info("IOException: {}", e.getMessage());
      throw new TlsClientException("IOException: socket creation error.", e);
    }
  }

  private static void sslHandshake(final SSLSocket clientSSLSocket)
      throws IOException, TlsConnectionException, TlsClientException {
    try {
      log.info(
          "Starting handshake from: {} to remote server socket: {}...",
          clientSSLSocket.getLocalSocketAddress(),
          clientSSLSocket.getRemoteSocketAddress());
      clientSSLSocket.startHandshake();
      log.info(
          "...handshake successfully started. To send application data implement:"
              + " clientSSLSocket.getOutputStream().write()");
    } catch (final TlsFatalAlertReceived | SocketTimeoutException e) {
      log.info("No ssl connection established: {}", e.getMessage());
      throw new TlsConnectionException("No ssl connection established.", e);
    } catch (final SocketException e) {
      log.info("SocketException: {}", e.getMessage());
      if (e.getMessage().startsWith("Connection refused")) {
        throw new TlsClientException("SocketException: Connection refused.", e);
      } else {
        throw new TlsConnectionException(
            "No ssl connection established. SocketException: " + e.getMessage(), e);
      }
    }
  }

  private void sslConnect(
      final InetAddress serverAddress,
      final int serverPort,
      final SSLSocket clientSSLSocket,
      final String[] ciphersSuites)
      throws TlsClientException {
    try {
      final SSLParameters sslParameters = clientSSLSocket.getSSLParameters();

      if (tlsSettings.isSniEnabled()) {
        final String hostName = serverAddress.getHostName();
        if (StringUtils.isNotBlank(hostName) && !serverAddress.isLoopbackAddress()) {
          log.info("Try to connect with S(erver)N(ame)I(ndication):  \"{}\"", hostName);
          final SNIHostName sniHostName = new SNIHostName(hostName);
          sslParameters.setServerNames(List.of(sniHostName));
        }
      }

      sslParameters.setCipherSuites(ciphersSuites);
      clientSSLSocket.setSSLParameters(sslParameters);
      clientSSLSocket.setEnabledProtocols(tlsSettings.getEnabledProtocols());

      clientSSLSocket.setUseClientMode(true);
      clientSSLSocket.addHandshakeCompletedListener(new TlsHandshakeCompletedListener());
      log.info(
          "Try to connect to socket: {}:{} and timeout {}s...",
          serverAddress,
          serverPort,
          ocspDelaySeconds);
      clientSSLSocket.connect(
          new InetSocketAddress(serverAddress, serverPort), ocspDelaySeconds * 1000);
      log.info("... socket connect successful.");
    } catch (final IOException e) {
      log.info("IOException: {}", e.getMessage());
      throw new TlsClientException("SSLSocket connection error.", e);
    }
  }
}
