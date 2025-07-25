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

package de.gematik.pki.pkits.tsl.provider.controller;

import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class TslConfigController {

  private final TslConfigHolder tslConfigHolder;
  private final TslRequestHistory tslRequestHistory;

  @Operation(summary = "Configure the TSL Provider.")
  @PostMapping(value = PkitsConstants.TSL_WEBSERVER_CONFIG_ENDPOINT)
  public void tslConfig(final @RequestBody TslProviderConfigDto tslProviderConfigDto) {
    log.info("Tsl ConfigurationRequest received");
    processConfigurationRequest(tslProviderConfigDto);
    log.info("TSL ConfigurationRequest processed (and history cleared).");
  }

  @Operation(summary = "Clear configuration of the TSL Provider.")
  @DeleteMapping(value = PkitsConstants.TSL_WEBSERVER_CLEAR_ENDPOINT)
  public void tslClear() {
    log.info("Tsl ClearRequest received");
    processConfigurationRequest(null);
    log.info("TSL ClearRequest processed (and history cleared).");
  }

  private void processConfigurationRequest(final TslProviderConfigDto tslProviderConfigDto) {
    log.info("TslProviderConfigDto: {}", tslProviderConfigDto);

    tslConfigHolder.setTslProviderConfigDto(tslProviderConfigDto);
    tslRequestHistory.deleteAll();
  }
}
