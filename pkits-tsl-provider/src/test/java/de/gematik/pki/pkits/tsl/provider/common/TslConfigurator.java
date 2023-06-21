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

package de.gematik.pki.pkits.tsl.provider.common;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.apache.http.HttpStatus;

public class TslConfigurator {

  public static void configureTsl(
      final int tslPort, final byte[] tslBytes, final TslDownloadPoint activeTslDownloadPoint)
      throws UnirestException {
    final TslProviderConfigDto tslProviderConfigDto =
        new TslProviderConfigDto(
            tslBytes, activeTslDownloadPoint, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200);

    final String jsonContent = PkitsCommonUtils.createJsonContent(tslProviderConfigDto);

    final HttpResponse<String> response =
        Unirest.post("http://localhost:" + tslPort + WEBSERVER_CONFIG_ENDPOINT)
            .body(jsonContent)
            .asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
  }
}
