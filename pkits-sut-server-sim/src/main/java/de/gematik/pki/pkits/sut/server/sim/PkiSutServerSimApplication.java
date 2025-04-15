/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.sut.server.sim;

import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.sut.server.sim.configs.OcspConfig;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.springframework.boot.Banner.Mode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@SpringBootApplication
public class PkiSutServerSimApplication implements SecurityFilterChain {

  static {
    /* {@link sun.security.ssl.NamedGroup#SECP192_R1} */
    System.setProperty(
        "jdk.tls.namedGroups",
        "brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp256r1, secp384r1");

    Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
  }

  @Getter private static OcspRespCache ocspRespCache;
  public static final String PRODUCT_TYPE = "Test";

  public PkiSutServerSimApplication(final OcspConfig ocspConfig) {
    ocspRespCache = new OcspRespCache(ocspConfig.getOcspGracePeriodSeconds()); // NOSONAR
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    return true;
  }

  @Override
  public List<Filter> getFilters() {
    return Collections.emptyList();
  }

  @EventListener(ApplicationReadyEvent.class)
  public void init() {
    log.info(
        "\n{}\n",
        PkitsCommonUtils.getBannerStr(
            PkiSutServerSimApplication.class, "bannerFormatSutServer.txt"));
  }

  public static void main(final String[] args) {
    final SpringApplication app = new SpringApplication(PkiSutServerSimApplication.class);
    app.setBannerMode(Mode.OFF);
    app.run(args);
  }
}
