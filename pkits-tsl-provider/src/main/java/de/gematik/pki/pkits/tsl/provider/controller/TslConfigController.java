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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslConfigRequestDto;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class TslConfigController {

  private final TslConfigHolder tslConfigHolder;

  @PostMapping(value = WEBSERVER_CONFIG_ENDPOINT)
  public void tslConfig(final HttpServletRequest request) throws IOException {
    log.info("Tsl ConfigurationRequest received");
    final TslConfigRequestDto tslConfigRequest =
        new ObjectMapper().readValue(request.getInputStream(), TslConfigRequestDto.class);
    processConfigurationRequest(tslConfigRequest);
  }

  private void processConfigurationRequest(final TslConfigRequestDto configRequest) {
    log.info("TslProviderConfigDto: {}", configRequest);
    if (bearerTokenIsValid(configRequest.getBearerToken())) {
      tslConfigHolder.setTslProviderConfigDto(configRequest.getTslProviderConfigDto());
    } else {
      log.info(
          "Invalid bearer token received: {}, expected: {}",
          configRequest.getBearerToken(),
          tslConfigHolder.getBearerToken());
    }
  }

  private boolean bearerTokenIsValid(final String receivedToken) {
    return (tslConfigHolder.getBearerToken().compareTo(receivedToken)) == 0;
  }
}
