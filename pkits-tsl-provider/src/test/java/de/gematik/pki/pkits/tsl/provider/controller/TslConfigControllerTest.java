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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.utils.ResourceReader;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
import java.nio.charset.StandardCharsets;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@Slf4j
@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
class TslConfigControllerTest {

  @LocalServerPort private int localServerPort;
  @Autowired private TslConfigHolder tslConfigHolder;

  private static final String TSL_FILEPATH = "TSL_default.xml";

  @BeforeEach
  public void beforeEach() {
    invalidateTslProviderConfiguration();
  }

  @Test
  void tslConfigNew() {
    final String WEBSERVER_CONFIG_URL =
        "http://localhost:" + localServerPort + WEBSERVER_CONFIG_ENDPOINT;

    final byte[] tslBytes =
        ResourceReader.getFileFromResourceAsBytes(TSL_FILEPATH, this.getClass());
    final TslProviderConfigDto tslProviderConfig =
        new TslProviderConfigDto(tslBytes, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200);

    log.info("new TslProviderConfig: {}", tslProviderConfig);
    final String jsonContent = PkitsCommonUtils.createJsonContent(tslProviderConfig);

    final HttpResponse<String> response =
        Unirest.post(WEBSERVER_CONFIG_URL).body(jsonContent).asString();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(tslConfigHolder.getTslProviderConfigDto().getTslBytes()).hasSameSizeAs(tslBytes);
  }

  private void invalidateTslProviderConfiguration() {
    final byte[] tslBytes = "this is not a TSL :-)".getBytes(StandardCharsets.UTF_8);
    tslConfigHolder.setTslProviderConfigDto(
        new TslProviderConfigDto(tslBytes, TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200));
  }
}
