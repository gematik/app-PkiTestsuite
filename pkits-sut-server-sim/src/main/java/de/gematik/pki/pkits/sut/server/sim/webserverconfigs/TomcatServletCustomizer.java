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

package de.gematik.pki.pkits.sut.server.sim.webserverconfigs;

import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TomcatServletCustomizer
    implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

  @Value("${server.ssl.enabled}")
  private boolean sslenabled;

  @Value("${server.ssl.protocol}")
  private String sslprotocol;

  @Value("${server.ssl.ciphers}")
  private String sslciphers;

  @Override
  public void customize(final TomcatServletWebServerFactory factory) {
    log.debug("customize ------------------------------------");
    if (sslenabled) {
      log.debug("ssl is enabled");

      factory.addConnectorCustomizers(
          connector -> {
            final Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
            protocol.setTrustManagerClassName(HandshakeInterceptor.class.getCanonicalName());
            protocol.setSslProtocol(sslprotocol);
            protocol.setCiphers(sslciphers);
          });
    }
  }
}
