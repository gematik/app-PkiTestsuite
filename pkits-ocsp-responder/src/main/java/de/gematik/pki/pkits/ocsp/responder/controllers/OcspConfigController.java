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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.OcspConfigRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class OcspConfigController {

  private final OcspResponseConfigHolder ocspResponseConfigHolder;
  private final OcspRequestHistory ocspRequestHistory;

  @PostMapping(value = WEBSERVER_CONFIG_ENDPOINT)
  public void ocspConfig(final HttpServletRequest request) throws IOException {
    log.info("Ocsp ConfigurationRequest received");
    final byte[] ocspConfigRequestByte =
        new ObjectMapper().readValue(request.getInputStream(), byte[].class);
    final OcspConfigRequestDto ocspConfigRequest = bytesToDto(ocspConfigRequestByte);
    processConfigurationRequest(ocspConfigRequest);
    log.info("Ocsp ConfigurationRequest processed (and history cleared).");
  }

  private void processConfigurationRequest(final OcspConfigRequestDto configRequest) {
    log.info("ConfigurationRequest: {}", configRequest);
    if (bearerTokenIsValid(configRequest.getBearerToken())) {
      ocspResponseConfigHolder.setOcspResponderConfigDto(configRequest.getOcspResponderConfigDto());
      ocspRequestHistory.deleteAll();
    } else {
      log.info(
          "Invalid bearer token received: {}, expected: {}",
          configRequest.getBearerToken(),
          ocspResponseConfigHolder.getBearerToken());
    }
  }

  private boolean bearerTokenIsValid(final String receivedToken) {
    return (ocspResponseConfigHolder.getBearerToken().compareTo(receivedToken)) == 0;
  }

  public static OcspConfigRequestDto bytesToDto(final byte[] bytes) {
    return (OcspConfigRequestDto) PkitsCommonUtils.bytesToObject(bytes);
  }
}
