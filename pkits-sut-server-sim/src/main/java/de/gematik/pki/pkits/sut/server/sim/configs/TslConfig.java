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

package de.gematik.pki.pkits.sut.server.sim.configs;

import de.gematik.pki.pkits.sut.server.sim.exceptions.TosException;
import java.net.MalformedURLException;
import java.net.URL;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslConfig {

  public static String buildTslDownloadUrl(@NonNull final URL tslUrl) {
    final String systemEnvTslProviderPort = System.getProperty("TSL_PROVIDER_PORT");
    if ((systemEnvTslProviderPort != null) && (!systemEnvTslProviderPort.isEmpty())) {
      try {
        return new URL(
                tslUrl.getProtocol(),
                tslUrl.getHost(),
                Integer.parseUnsignedInt(systemEnvTslProviderPort),
                tslUrl.getFile())
            .toString();
      } catch (final MalformedURLException e) {
        log.error("Error in config file for value {}.", tslUrl);
        throw new TosException("Building tsl download url not possible.", e);
      }
    }
    return tslUrl.toString();
  }
}
