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

package de.gematik.pki.pkits.ocsp.responder.controllers;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.OcspResponseConfigHolder;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
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

  private final ObjectReader reader = new ObjectMapper().readerFor(byte[].class);

  @PostMapping(value = WEBSERVER_CONFIG_ENDPOINT)
  public void ocspConfig(final HttpServletRequest request) throws IOException {
    log.info("Ocsp ConfigurationRequest received");
    final byte[] ocspConfigRequestByte = reader.readValue(request.getInputStream());
    final OcspResponderConfigDto ocspResponderConfigDto = bytesToDto(ocspConfigRequestByte);
    processConfigurationRequest(ocspResponderConfigDto);
    log.info("Ocsp ConfigurationRequest processed (and history cleared).");
  }

  private void processConfigurationRequest(final OcspResponderConfigDto ocspResponderConfigDto) {
    log.info("ConfigurationRequest: {}", ocspResponderConfigDto);

    ocspResponseConfigHolder.setOcspResponderConfigDto(ocspResponderConfigDto);
    ocspRequestHistory.deleteAll();
  }

  public static OcspResponderConfigDto bytesToDto(final byte[] bytes) {
    return (OcspResponderConfigDto) PkitsCommonUtils.bytesToObject(bytes);
  }
}
