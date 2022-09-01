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

package de.gematik.pki.pkits.idp.client;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.pki.pkits.common.PkiCommonException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class IdpClientApplication {

  private static PkiIdentity createPkiIdentity(final Path certPath, final String passw) {
    try {
      return CryptoLoader.getIdentityFromP12(Files.readAllBytes(certPath), passw);
    } catch (final IOException e) {
      throw new PkiCommonException("Could not get identity from p12.", e);
    }
  }

  private static void doLogin(final String ddUrl, final PkiIdentity pkiIdentity) {
    final String CLIENT_ID_E_REZEPT_APP = "gematikTestPs";
    final String REDIRECT_URI_E_REZEPT_APP = "http://test-ps.gematik.de/erezept";

    BrainpoolCurves.init();

    final IdpClient idpClient =
        IdpClient.builder()
            .clientId(CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl(ddUrl)
            .redirectUrl(REDIRECT_URI_E_REZEPT_APP)
            .build();

    idpClient.initialize();

    final IdpTokenResult tokenResponse = idpClient.login(pkiIdentity);
    Objects.requireNonNull(tokenResponse);

    log.info(tokenResponse.getAccessToken().getRawString());
  }

  public static void main(final String[] args) {

    log.info("IDP args: {}", StringUtils.joinWith(" | ", (Object[]) args));

    final String ddUrl = args[0];
    final Path certPath = Path.of(args[1]);
    final String password = args[2];

    log.info("IDP login: start");

    doLogin(ddUrl, createPkiIdentity(certPath, password));

    log.info("IDP login: end");
  }
}
