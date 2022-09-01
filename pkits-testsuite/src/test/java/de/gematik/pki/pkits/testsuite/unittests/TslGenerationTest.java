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

package de.gematik.pki.pkits.testsuite.unittests;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.pkits.testsuite.common.tsl.TslGeneration;
import de.gematik.pki.pkits.testsuite.common.tsl.TslModification;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Scanner;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

class TslGenerationTest {

  @Test
  void createTslFromFile() throws DatatypeConfigurationException, IOException {
    final Path destFilePath = Path.of("target/unittest_createTslFromFile.xml");
    final String newSsp = "http://my.new-cool-service-supply-point:5544/ocsp";
    final int modifiedSspAmountExpected = 140;
    final ZonedDateTime zdtUtcNow = ZonedDateTime.now(ZoneOffset.UTC);
    final int COMPARE_LEN = "yyyy-mm-ddThh:mm".length();

    final TslModification tslMod =
        TslModification.builder()
            .sequenceNr(1)
            .tspName("")
            .newSsp(newSsp)
            .tslDownloadUrlPrimary("tslProvUri")
            .tslDownloadUrlBackup("")
            .issueDate(zdtUtcNow)
            .nextUpdate(null)
            .daysUntilNextUpdate(30)
            .build();
    final Path tslSignerPath =
        Path.of(
            "../testDataTemplates/certificates/ecc/trustAnchor/TSL-Signing-Unit-8-TEST-ONLY.p12");
    final byte[] tslBytes =
        TslGeneration.createTslFromFile(
            Path.of("../testDataTemplates/tsl/tslTemplateEcc.xml"), tslMod, tslSignerPath, "00");
    Files.write(destFilePath, tslBytes);

    assertThat(countStringInFile(destFilePath, newSsp)).isEqualTo(modifiedSspAmountExpected);
    final String dateTimeWithoutSeconds =
        TslReader.getIssueDate(TslReader.getTsl(destFilePath).orElseThrow())
            .toString()
            .substring(0, COMPARE_LEN);
    assertThat(zdtUtcNow.toString()).contains(dateTimeWithoutSeconds);
  }

  private static int countStringInFile(@NonNull final Path filePath, @NonNull final String expected)
      throws IOException {
    final Scanner scanner = new Scanner(Files.newInputStream(filePath));
    int cnt = 0;
    while (scanner.hasNextLine()) {
      final String line = scanner.nextLine();
      cnt += StringUtils.countMatches(line, expected);
    }
    return cnt;
  }
}
