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

import de.gematik.pki.pkits.common.PkiCommonException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLContext;
import org.apache.http.ssl.SSLContextBuilder;

public class SSLContextProvider {

  public SSLContext createSSLContext(final Path keystore, final String keystorePassword) {

    try (final InputStream is = Files.newInputStream(keystore)) {
      final KeyStore realKeyStore = KeyStore.getInstance("PKCS12");
      realKeyStore.load(is, keystorePassword.toCharArray());

      return SSLContextBuilder.create()
          .loadKeyMaterial(realKeyStore, keystorePassword.toCharArray())
          .build();

    } catch (final NoSuchAlgorithmException
        | KeyManagementException
        | KeyStoreException
        | UnrecoverableKeyException
        | CertificateException
        | IOException e) {
      throw new PkiCommonException("Could not create SSL context", e);
    }
  }
}
