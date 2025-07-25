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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TU_ECC_ONLY_TSL;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TU_TSL;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.StandardTslOperation.StandardTslOperationConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Scanner;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

class StandardTslOperationTest {
  @Test
  void createRSATslFromFile() throws IOException {
    createTslFromFile(ARVATO_TU_TSL, false);
  }

  @Test
  void createECCTslFromFile() throws IOException {
    createTslFromFile(ARVATO_TU_ECC_ONLY_TSL, true);
  }

  private void createTslFromFile(Path path, boolean eccOnly) throws IOException {
    final Path destFilePath = Path.of("pkits-tsl-generator/target/unittest_createTslFromFile.xml");
    final String newSsp = "http://my.new-cool-service-supply-point:5544/ocsp";

    final int minModifiedSspAmountExpected =
        new TslInformationProvider(TslReader.getTslUnsigned(path))
            .getFilteredTspServices(TslConstants.STI_CA_LIST)
            .size();

    final ZonedDateTime now = GemLibPkiUtils.now();
    final int COMPARE_LEN = "yyyy-mm-ddThh:mm".length();

    final StandardTslOperationConfig standardTslOperationConfig =
        StandardTslOperationConfig.builder()
            .tslSeqNr(1)
            .tspName("")
            .newSsp(newSsp)
            .tslDownloadUrlPrimary("tslProvUri")
            .tslDownloadUrlBackup("")
            .issueDate(now)
            .nextUpdate(null)
            .daysUntilNextUpdate(30)
            .build();

    final TslOperation standardTslOperation = new StandardTslOperation(standardTslOperationConfig);
    final TslOperation signTslOperation =
        new SignTslOperation(
            PkitsTestDataConstants.DEFAULT_TSL_SIGNER,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    final TslOperation aggregateTslOperation =
        new AggregateTslOperation(standardTslOperation, signTslOperation);

    final TslContainer tslContainer =
        aggregateTslOperation.apply(CreateTslTemplate.defaultTsl(eccOnly));

    final byte[] tslBytes = tslContainer.getAsTslUnsignedBytes();
    Files.write(destFilePath, tslBytes);

    assertThat(countStringInFile(destFilePath, newSsp)).isGreaterThan(minModifiedSspAmountExpected);
    final String dateTimeWithoutSeconds =
        TslReader.getIssueDate(TslReader.getTslUnsigned(destFilePath))
            .toString()
            .substring(0, COMPARE_LEN);
    assertThat(now.toString()).contains(dateTimeWithoutSeconds);
  }

  private static int countStringInFile(@NonNull final Path filePath, @NonNull final String expected)
      throws IOException {
    final Scanner scanner = new Scanner(Files.newInputStream(filePath), StandardCharsets.UTF_8);
    int cnt = 0;
    while (scanner.hasNextLine()) {
      final String line = scanner.nextLine();
      cnt += StringUtils.countMatches(line, expected);
    }
    return cnt;
  }
}
