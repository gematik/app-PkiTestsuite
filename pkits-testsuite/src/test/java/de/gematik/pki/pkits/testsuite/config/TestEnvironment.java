/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.config;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto.TslProviderEndpointsConfig;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TestEnvironment {

  public static void clearOspResponderHistory(final String ocspRespUri) {
    OcspResponderManager.clearOcspHistory(ocspRespUri);
  }

  public static void configureTslProvider(
      final String tslProvUri,
      final byte[] tsl,
      final TslDownloadPoint tslDownloadPoint,
      final TslProviderEndpointsConfig tslProviderEndpointsConfig) {

    final TslProviderConfigDto tslProviderConfigDto =
        new TslProviderConfigDto(tsl, tslDownloadPoint, tslProviderEndpointsConfig);

    TslProviderManager.configure(tslProvUri, tslProviderConfigDto);

    log.info(
        "TslProvider configured with TSL ({} bytes) and tslProviderEndpointsConfig = {}.",
        tsl.length,
        tslProviderEndpointsConfig);
  }

  public static void clearTslProviderConfig(final String tslProvUri) {

    PkitsCommonUtils.checkHealth(log, "TslProvider", tslProvUri);
    TslProviderManager.clear(tslProvUri);

    log.info("TslProvider configuration cleared.");
  }

  public static void configureOcspResponder(
      final String ocspRespUri, final OcspResponderConfigDto ocspResponderConfig) {

    OcspResponderManager.configure(ocspRespUri, ocspResponderConfig);

    log.info(
        "OcspResponder configured with cert serialNr: {}).",
        ocspResponderConfig.getEeCert().getSerialNumber());
  }

  public static void clearOcspResponderConfig(final String ocspRespUri) {

    PkitsCommonUtils.checkHealth(log, "OcspResponder", ocspRespUri);
    OcspResponderManager.clear(ocspRespUri);

    log.info("OcspResponder configuration cleared.");
  }
}
