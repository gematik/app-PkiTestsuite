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

package de.gematik.pki.pkits.tls.client;

import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
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
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

@Builder
@Slf4j
public class TlsConnection {

  private final String clientKeystorePassw;
  private final InetAddress serverAddress;
  private final int sutServerPort;
  private final TlsSettings tlsSettings;

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
          TlsClientException {
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
          TlsClientException {

    final SSLContext sslContextClient =
        new SSLContextProvider().createSSLContext(clientKeystorePath, clientKeystorePassw);

    final P12Container p12Container =
        P12Reader.getContentFromP12(clientKeystorePath, clientKeystorePassw);

    final String algorithm = p12Container.getCertificate().getPublicKey().getAlgorithm();

    final String kfAlgorithm;
    final String[] ciphersSuites;
    if ("EC".equalsIgnoreCase(algorithm)) {
      System.setProperty(
          "jdk.tls.namedGroups", "brainpoolP256r1, brainpoolP384r1, brainpoolP512r1");
      ciphersSuites = tlsSettings.getEcCiphersSuites();
      kfAlgorithm = KeyManagerFactory.getDefaultAlgorithm();

    } else if ("RSA".equalsIgnoreCase(algorithm)) {
      ciphersSuites = tlsSettings.getRsaCiphersSuites();
      System.setProperty("jdk.tls.namedGroups", "ffdhe2048");
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
    sslContextClient.init(kmf.getKeyManagers(), new TrustManager[] {new BlindTrustManager()}, null);

    log.info("algorithm: {}, ciphersSuites: {}", algorithm, Arrays.asList(ciphersSuites));

    try (final SSLSocket clientSSLSocket =
        (SSLSocket) sslContextClient.getSocketFactory().createSocket(serverAddress, serverPort)) {
      log.info(
          "try to connect with cert \"{}\" to {}:{} ",
          clientKeystorePath,
          serverAddress,
          serverPort);

      final SSLParameters sslParameters = clientSSLSocket.getSSLParameters();
      sslParameters.setCipherSuites(ciphersSuites);

      clientSSLSocket.setSSLParameters(sslParameters);
      clientSSLSocket.setEnabledProtocols(tlsSettings.getEnabledProtocols());
      clientSSLSocket.setSoTimeout(tlsSettings.getSocketTimeoutMsec());
      clientSSLSocket.setUseClientMode(true);
      clientSSLSocket.addHandshakeCompletedListener(new TlsHandshakeCompletedListener());
      clientSSLSocket.startHandshake();
      log.info(
          "Handshake started. To send application data implement:"
              + " clientSSLSocket.getOutputStream().write()");
      log.info("Socket we connect from: {}", clientSSLSocket.getLocalSocketAddress());

    } catch (final IOException e) {
      throw new TlsClientException("Cannot create SSL socket", e);
    }
  }
}
