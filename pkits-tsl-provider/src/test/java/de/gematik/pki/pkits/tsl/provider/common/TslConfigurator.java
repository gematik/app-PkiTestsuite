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

package de.gematik.pki.pkits.tsl.provider.common;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderEndpointsConfig;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import org.apache.hc.core5.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

public class TslConfigurator {

  public static void configureTsl(final int tslPort, final byte[] tslBytes)
      throws UnirestException {
    final TslProviderConfigDto tslProviderConfigDto =
        new TslProviderConfigDto(tslBytes, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200);

    final String jsonContent = PkitsCommonUtils.createJsonContent(tslProviderConfigDto);

    final HttpResponse<String> response =
        Unirest.post("http://localhost:" + tslPort + PkitsConstants.TSL_WEBSERVER_CONFIG_ENDPOINT)
            .body(jsonContent)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asString();
    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
  }
}
