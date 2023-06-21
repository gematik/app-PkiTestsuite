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

package de.gematik.pki.pkits.testsuite.testutils;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
public class InitialTestDataTest extends ApprovalTestsBase {

  @Test
  void buildInitialTslAndTa() throws IOException {

    final int seqNr = 1;

    final TslGenerator tslGen = newTslGenerator("initialTsl");
    tslGen.setTslSeqNr(seqNr);
    final TslDownload tslDownload = tslGen.getStandardTslDownload(CreateTslTemplate.defaultTsl());

    final Path initialTslPath = Path.of("./out/initialTsl.xml");
    log.info("copying initial Tsl to: {}", initialTslPath);
    Files.write(initialTslPath, tslDownload.getTslBytes());

    final Path initialTaPath = Path.of("./out/initialTrustAnchor.pem");
    log.info("copying initial trustAnchor to: {}", initialTaPath);
    Files.write(
        initialTaPath,
        GemLibPkiUtils.readContent(TestSuiteConstants.VALID_ISSUER_CERT_TSL_CA8_PATH));
  }
}
