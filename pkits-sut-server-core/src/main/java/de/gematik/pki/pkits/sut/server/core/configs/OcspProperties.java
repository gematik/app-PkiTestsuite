/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.sut.server.core.configs;

import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;

import de.gematik.pki.pkits.sut.server.core.exceptions.TosException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Objects;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@RequiredArgsConstructor
@ConfigurationProperties("ocsp")
public class OcspProperties {

  @Value("${ocsp.enabled}")
  private boolean ocspEnabled;

  @Value("${ocsp.service-url}")
  private String ocspServiceUrl;

  @Value("${ocsp.grace-period-seconds:30}")
  private int ocspGracePeriodSeconds;

  @Value("5")
  private int toleranceProducedAtPastSeconds;

  @Value("3")
  private int toleranceProducedAtFutureSeconds;

  @Value("${ocsp.ocsp-timeout-seconds:10}")
  private int ocspTimeoutSeconds;

  @Value("${ocsp.tolerate-ocsp-failure:false}")
  private boolean tolerateOcspFailure;

  public URL readServiceUrl() {
    return Objects.requireNonNullElseGet(getUrlFromEnvironment(), this::getUrlFromConfig);
  }

  private URL getUrlFromConfig() {
    try {
      return URI.create(ocspServiceUrl).toURL();
    } catch (final IllegalArgumentException | MalformedURLException e) {
      throw new TosException("Cannot create SSP URL", e);
    }
  }

  private URL getUrlFromEnvironment() {
    final String systemEnvOcspResponderPort = System.getProperty("OCSP_RESPONDER_PORT");
    if ((systemEnvOcspResponderPort != null) && (!systemEnvOcspResponderPort.isEmpty())) {
      try {
        return URI.create(
                "http://localhost:"
                    + Integer.parseUnsignedInt(systemEnvOcspResponderPort)
                    + OCSP_SSP_ENDPOINT)
            .toURL();
      } catch (final IllegalArgumentException | MalformedURLException e) {
        throw new TosException("Cannot create SSP URL", e);
      }
    }
    return null;
  }
}
