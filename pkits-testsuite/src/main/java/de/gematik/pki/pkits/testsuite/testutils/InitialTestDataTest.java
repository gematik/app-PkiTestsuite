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

package de.gematik.pki.pkits.testsuite.testutils;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.getHttpAddressString;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslDownloadGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.config.OcspResponderConfig;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TslProviderConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@Slf4j
public class InitialTestDataTest {

  @Test
  @DisplayName("Build initial TSL and trust anchor")
  void buildInitialTslAndTa() throws IOException {

    final int tslSeqNr = 1;
    final int tslDaysUntilNextupdate = Integer.parseInt(System.getProperty("tsl.days", "90"));

    final TslProviderConfig tslProvider = TestConfigManager.getTestSuiteConfig().getTslProvider();

    final OcspResponderConfig ocspResponderConfig =
        TestConfigManager.getTestSuiteConfig().getOcspResponder();

    final TslDownloadGenerator tslDownloadGenerator =
        TslDownloadGenerator.builder()
            .tslSeqNr(tslSeqNr)
            .tslDaysUntilNextupdate(tslDaysUntilNextupdate)
            .tslName("initialTsl")
            .tslSigner(PkitsTestDataConstants.DEFAULT_TSL_SIGNER)
            .trustAnchor(PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR)
            .tslProviderUri(
                getHttpAddressString(tslProvider.getIpAddressOrFqdn(), tslProvider.getPort()))
            .ocspResponderUri(
                getHttpAddressString(
                    ocspResponderConfig.getIpAddressOrFqdn(), ocspResponderConfig.getPort()))
            .ocspSigner(PkitsTestDataConstants.DEFAULT_OCSP_SIGNER)
            .build();

    final TslDownload tslDownload =
        tslDownloadGenerator.getStandardTslDownload(CreateTslTemplate.defaultTsl(false));

    final Path initialTslPath = Path.of("./out/initialTsl.xml");
    log.info("copying initial Tsl to: {}", initialTslPath);
    Files.write(initialTslPath, tslDownload.getTslBytes());

    final Path initialTaPath = Path.of("./out/initialTrustAnchor.pem");
    log.info("copying initial trustAnchor to: {}", initialTaPath);
    Files.write(
        initialTaPath, GemLibPkiUtils.certToBytes(PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR));
  }
}
