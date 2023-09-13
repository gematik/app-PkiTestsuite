/*
 * Copyright 2023 gematik GmbH
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

import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos;
import java.nio.file.Path;
import lombok.Getter;
import picocli.CommandLine;
import picocli.CommandLine.Help.Visibility;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

@Getter
class PkitsTestsuiteRunnerParams {

  @CommandLine.Option(
      names = {"-tf", "--tests-file"},
      description = "the file with tests to run",
      defaultValue = ListApprovalTestsAndAfos.ALL_TESTCASES_FILENAME,
      showDefaultValue = Visibility.ALWAYS)
  Path testCasesFile;

  @CommandLine.Option(
      names = {"-faf", "--failed-and-aborted-file"},
      description =
          "Save all failed or aborted tests to this file. The file can be used as parameter for the"
              + "CLI option --tests-file.",
      defaultValue = ListApprovalTestsAndAfos.ALL_FAILED_OR_ABORTED_TESTCASES_FILENAME,
      showDefaultValue = Visibility.ALWAYS)
  Path failedTestCases;

  @CommandLine.Option(
      names = {"-tn", "--tests-names"},
      description =
          "comma separated list of names to run, for example"
              + " \"verifyUseCaseCertsValid,TslApprovalTestsIT,TslSignerApprovalTestsIT#checkInitialState\"")
  String testCasesNames;

  int percent;
  @Spec CommandSpec spec;

  @CommandLine.Option(
      names = {"-p", "--percent"},
      paramLabel = "NUMBER",
      description =
          "Execute only proportion of randomly selected tests from all tests that were passed via"
              + " --tests-file or --tests-names). It is a number from 1 to 100. At least 1 test"
              + " from passed will be selected.",
      defaultValue = "100",
      showDefaultValue = Visibility.ALWAYS)
  public void setPercentNumber(final int value) {
    final boolean isValid = (1 <= value) && (value <= 100);
    if (!isValid) {
      throw new ParameterException(
          spec.commandLine(),
          String.format(
              "Invalid value '%s' for option '-p (--percent)': "
                  + "value is not between 1 and 100.",
              value));
    }
    this.percent = value;
  }

  @CommandLine.Option(
      names = {"-h", "--help"},
      usageHelp = true,
      description = "display a help message")
  boolean helpRequested = false;

  @CommandLine.Option(
      names = {"--no-pdf-report"},
      description = "Do not generate report as PDF")
  boolean skipPdfReport = false;
}
