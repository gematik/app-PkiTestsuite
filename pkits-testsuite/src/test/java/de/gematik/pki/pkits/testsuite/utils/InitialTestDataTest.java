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

package de.gematik.pki.pkits.testsuite.utils;

import static de.gematik.pki.pkits.common.PkitsConstants.GEMATIK_TEST_TSP;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslGeneration;
import de.gematik.pki.pkits.testsuite.common.tsl.TslModification;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.config.TslSettings;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.function.Function;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
class InitialTestDataTest {

  private String getUrl(final String hostname, final int port) {
    return "http://%s:%d".formatted(hostname, port);
  }

  @Test
  void buildInitialTslAndVa() throws DatatypeConfigurationException, IOException {

    final TslSettings tslCfg =
        TestConfigManager.getTestSuiteConfig().getTestSuiteParameter().getTslSettings();
    final TestSuiteConfig tsCfg = TestConfigManager.getTestSuiteConfig();

    final int seqNr = 1;

    final String tslProvUri =
        getUrl(tsCfg.getTslProvider().getIpAddressOrFqdn(), tsCfg.getTslProvider().getPort());
    final String ocspRespUri =
        getUrl(tsCfg.getOcspResponder().getIpAddressOrFqdn(), tsCfg.getOcspResponder().getPort());

    final Function<String, String> endpointFunc =
        (endpoint) -> "%s%s?%s=%d".formatted(tslProvUri, endpoint, TSL_SEQNR_PARAM_ENDPOINT, seqNr);

    final TslModification tslMod =
        TslModification.builder()
            .sequenceNr(seqNr)
            .tspName(GEMATIK_TEST_TSP)
            .newSsp(ocspRespUri + OCSP_SSP_ENDPOINT + "/" + seqNr)
            .tslDownloadUrlPrimary(endpointFunc.apply(TSL_XML_PRIMARY_ENDPOINT))
            .tslDownloadUrlBackup(endpointFunc.apply(TSL_XML_BACKUP_ENDPOINT))
            .issueDate(ZonedDateTime.now(ZoneOffset.UTC))
            .nextUpdate(null)
            .daysUntilNextUpdate(90)
            .build();

    final byte[] tslBytes =
        TslGeneration.createTslFromFile(
            tslCfg.getDefaultTemplate(),
            tslMod,
            tslCfg.getSigner(),
            tslCfg.getSignerPassword(),
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);
    assertThat(tslBytes).isNotEmpty().isNotNull();

    final Path initialTslPath = Path.of("../out/initialTsl.xml");
    log.info("copying initial Tsl to: {}", initialTslPath);
    Files.write(initialTslPath, tslBytes);

    final Path initialTaPath = Path.of("../out/initialTrustAnchor.pem");
    log.info("copying initial trustAnchor to: {}", initialTaPath);
    Files.write(
        initialTaPath,
        PkitsCommonUtils.readContent(
            "../testDataTemplates/certificates/ecc/trustAnchor/GEM.TSL-CA8-TEST-ONLY.pem"));
  }
}
