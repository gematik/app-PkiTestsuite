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

package de.gematik.pki.pkits.testsuite.config;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderEndpointsConfig;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TestEnvironment {

  public static void configureTslProvider(
      final String tslProvUri,
      final byte[] tslBytes,
      final TslProviderEndpointsConfig tslProviderEndpointsConfig) {

    final TslProviderConfigDto tslProviderConfigDto =
        new TslProviderConfigDto(tslBytes, tslProviderEndpointsConfig);

    TslProviderManager.configure(tslProvUri, tslProviderConfigDto);

    log.info(
        "TslProvider configured with TSL ({} bytes) and tslProviderEndpointsConfig = {}.:: {}",
        tslBytes.length,
        tslProviderEndpointsConfig,
        PkitsTestSuiteUtils.getCallerTrace());
  }

  public static void clearTslProviderConfig(final String tslProvUri) {

    PkitsCommonUtils.checkHealth(log, "TslProvider", tslProvUri);
    TslProviderManager.clear(tslProvUri);

    log.info("TslProvider configuration cleared.");
  }

  public static void configureOcspResponder(
      final String ocspRespUri, final OcspResponderConfig ocspResponderConfig) {

    OcspResponderManager.configure(ocspRespUri, ocspResponderConfig);

    log.info(
        "OcspResponder configured with certSerialNrs {}.:: {}",
        String.join(
            ", ",
            ocspResponderConfig.getCertificateDtos().stream()
                .map(
                    cert ->
                        cert.getEeCert().getSerialNumber().toString()
                            + " ProducedAtDeltaMilliseconds: "
                            + cert.getProducedAtDeltaMilliseconds())
                .toList()),
        PkitsTestSuiteUtils.getCallerTrace());
  }

  public static void clearOcspResponderConfig(final String ocspRespUri) {

    PkitsCommonUtils.checkHealth(log, "OcspResponder", ocspRespUri);
    OcspResponderManager.clear(ocspRespUri);

    log.info("OcspResponder configuration cleared.");
  }
}
