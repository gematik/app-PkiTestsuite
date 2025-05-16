/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.testsuite.runner;

import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos;
import java.nio.file.Path;
import lombok.Getter;
import picocli.CommandLine.Help.Visibility;
import picocli.CommandLine.Option;

@Getter
class PkitsTestsuiteRunnerParams {

  @Option(
      names = {"-tf", "--tests-file"},
      description = "The file with tests to run.",
      defaultValue = ListApprovalTestsAndAfos.ALL_TESTCASES_FILENAME,
      showDefaultValue = Visibility.ALWAYS)
  Path testCasesFile;

  @Option(
      names = {"-faf", "--failed-and-aborted-file"},
      description =
          "Save all failed or aborted tests to this file. The file can be used as parameter for the"
              + "CLI option --tests-file.",
      defaultValue = ListApprovalTestsAndAfos.ALL_FAILED_OR_ABORTED_TESTCASES_FILENAME,
      showDefaultValue = Visibility.ALWAYS)
  Path failedTestCases;

  @Option(
      names = {"-tn", "--tests-names"},
      description =
          "Comma separated list of names to run, for example: \"verifyUseCaseCertsValid,"
              + " TslApprovalTestsIT, TslSignerApprovalTestsIT#checkInitialState\".")
  String testCasesNames;

  @Option(
      names = {"-h", "--help"},
      usageHelp = true,
      description = "Display this help message.")
  boolean helpRequested = false;

  @Option(
      names = {"-np", "--no-pdf-report"},
      description = "Do not generate report as PDF.")
  boolean skipPdfReport = false;
}
