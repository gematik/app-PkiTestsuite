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

package de.gematik.pki.pkits.sut.server.sim;

import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.pkits.sut.server.sim.configs.OcspConfig;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@SpringBootApplication
public class PkiSutServerSimApplication implements SecurityFilterChain {

  static {
    System.setProperty(
        "jdk.tls.namedGroups", "brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, ffdhe2048");

    Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
  }

  @Getter private static OcspRespCache ocspRespCache;

  public PkiSutServerSimApplication(final OcspConfig ocspConfig) {
    ocspRespCache = new OcspRespCache(ocspConfig.getOcspGracePeriodSeconds()); // NOSONAR
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    log.debug("in matches");
    return true;
  }

  @Override
  public List<Filter> getFilters() {
    log.debug("in getFilters");
    return Collections.emptyList();
  }

  // https://rules.sonarsource.com/java/RSPEC-4823 "This rule is deprecated, and will eventually
  // be removed."
  @SuppressWarnings("java:S4823")
  public static void main(final String[] args) {
    System.setProperty("javax.net.debug", "ssl:handshake");
    for (final Provider p : Security.getProviders()) {
      log.debug("P: {}", p);
    }
    SpringApplication.run(PkiSutServerSimApplication.class, args);
  }
}
