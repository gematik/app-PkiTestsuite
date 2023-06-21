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

package de.gematik.pki.pkits.testsuite.runner;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos.TestClassesContainer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
class PkitsTestsuiteRunnerUtilsTest {

  @Test
  void testGetTestToRunFromTestsFile() throws IOException {

    final String content =
        """
        +	de.gematik.pki.pkits.testsuite.approval.CertificateApprovalTests
        	verifyConnectCertsInvalid   Test use case with invalid certificates
        	verifyConnectCertsValid     Test use case with valid certificates

        -	de.gematik.pki.pkits.testsuite.approval.OcspApprovalTests
        	verifyInvalidCerIdInOcspResponse                   Test invalid cert id in OCSP response
        +	verifyOcspResponseWithNullParameterInCertId        Test OCSP response with null parameter in CertId

        	de.gematik.pki.pkits.testsuite.approval.TslApprovalTests
        -	verifyForBadCertificateOfTSPService                    Test bad CA certificate is not extractable from TSL
        +	verifyForWrongServiceInfoExtCertificateOfTSPService    Test CA certificate with missing service information extension in TSL
         	verifyTslSignatureInvalid                              Test TSL signature invalid - "to be signed block" with integrity violation
        """;

    final Path testFile = Path.of("sampleAllTests.txt");
    Files.writeString(testFile, content, StandardCharsets.UTF_8);

    final List<InputTestInfo> inputTestInfoList = PkitsTestsuiteRunnerUtils.readTests(testFile);

    assertThat(inputTestInfoList).hasSize(7);

    final List<InputTestInfo> selectedInputTests =
        inputTestInfoList.stream().filter(inputTestInfo -> inputTestInfo.selected).toList();

    final List<InputTestInfo> notSelectedInputTests =
        inputTestInfoList.stream().filter(inputTestInfo -> !inputTestInfo.selected).toList();

    assertThat(selectedInputTests).hasSize(4);
    assertThat(notSelectedInputTests).hasSize(3);

    assertThat(selectedInputTests.stream().map(inputTestInfo -> inputTestInfo.methodName).toList())
        .containsExactlyInAnyOrder(
            "verifyConnectCertsInvalid",
            "verifyConnectCertsValid",
            "verifyOcspResponseWithNullParameterInCertId",
            "verifyForWrongServiceInfoExtCertificateOfTSPService");

    final TestClassesContainer testClassesContainer =
        TestClassesContainer.readForDefaultTestClasses();

    final List<CustomTestInfo> selectedCustomTestInfoList =
        PkitsTestsuiteRunnerUtils.getTestToRun(inputTestInfoList, testClassesContainer);

    assertThat(selectedCustomTestInfoList).hasSize(4);
  }

  @Test
  void testGetTestToRunFromCliArgument() {

    final String testCasesNames =
        "CertificateApprovalTests," //   +3 tests
            + "verifyOcspGracePeriod, " // +1 test
            + "verifyUpdateTrustAnchor, " // DUPLICATE
            + "TslTaApprovalTests, " //  +5 tests
            + "verifyOcspGracePeriod," // DUPLICATE
            + "de.gematik.pki.pkits.testsuite.approval.CertificateApprovalTests"; // DUPLICATE

    // duplicate are not handled at this step
    final List<InputTestInfo> inputTestInfoList =
        PkitsTestsuiteRunnerUtils.parseTestNamesToInputTestInfos(testCasesNames);

    assertThat(inputTestInfoList).hasSize(6);

    final TestClassesContainer testClassesContainer =
        TestClassesContainer.readForDefaultTestClasses();

    final List<CustomTestInfo> selectedCustomTestInfoList =
        PkitsTestsuiteRunnerUtils.getTestToRun(inputTestInfoList, testClassesContainer);

    log.info(
        "selectedCustomTestInfoList\n{}",
        selectedCustomTestInfoList.stream()
            .map(CustomTestInfo::toString)
            .collect(Collectors.joining("\n")));

    assertThat(selectedCustomTestInfoList).hasSize(9);
  }
}
