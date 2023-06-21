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

import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos;
import java.nio.file.Path;
import lombok.Getter;
import picocli.CommandLine;

@Getter
class PkitsTestsuiteRunnerParams {

  @CommandLine.Option(
      names = {"-tf", "--tests-file"},
      description = "the file with tests to run")
  Path testCasesFile = ListApprovalTestsAndAfos.ALL_TESTCASES_FILE;

  @CommandLine.Option(
      names = {"-tn", "--tests-names"},
      description =
          "comma separated list of names to run, for example"
              + " \"verifyConnectCertsValid,TslApprovalTestsIT,TslSignerApprovalTestsIT#checkInitialState\"")
  String testCasesNames;

  @CommandLine.Option(
      names = {"-h", "--help"},
      usageHelp = true,
      description = "display a help message")
  private boolean helpRequested = false;

  @CommandLine.Option(
      names = {"--no-pdf-report"},
      description = "Do not generate report as PDF")
  private boolean skipPdfReport = false;
}
