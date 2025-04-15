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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigJsonDto;
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
public class OcspConfigController {

  private final OcspResponseConfigHolder ocspResponseConfigHolder;
  private final OcspRequestHistory ocspRequestHistory;

  @Operation(summary = "Configure the OCSP Responder.")
  @PostMapping(path = PkitsConstants.OCSP_WEBSERVER_CONFIG_ENDPOINT)
  public void ocspConfig(final @RequestBody OcspResponderConfigJsonDto jsonDto) {
    log.info("Ocsp ConfigurationRequest received");

    final OcspResponderConfig ocspResponderConfig = jsonDto.toConfig();

    processConfigurationRequest(ocspResponderConfig);

    log.info("Ocsp ConfigurationRequest processed (and history cleared).");
  }

  @Operation(summary = "Clear configuration of the OCSP Responder.")
  @DeleteMapping(path = PkitsConstants.OCSP_WEBSERVER_CLEAR_ENDPOINT)
  public void ocspClear() {
    log.info("Ocsp ClearRequest received");
    processConfigurationRequest(null);
    log.info("Ocsp ClearRequest processed (and history cleared).");
  }

  private void processConfigurationRequest(final OcspResponderConfig ocspResponderConfig) {
    log.info("ConfigurationRequest: {}", ocspResponderConfig);

    ocspResponseConfigHolder.setOcspResponderConfig(ocspResponderConfig);
    ocspRequestHistory.deleteAll();
  }
}
