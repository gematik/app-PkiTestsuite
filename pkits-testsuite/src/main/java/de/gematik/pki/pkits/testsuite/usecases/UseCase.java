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

package de.gematik.pki.pkits.testsuite.usecases;

import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.config.TestObjectConfig;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.ssh.SshUseCaseApplication;
import de.gematik.pki.pkits.tls.client.TlsClientApplication;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class UseCase {

  public static int exec(final Path eeCertPath, final TestSuiteConfig testSuiteConfig) {

    final TestObjectConfig testObjectConfig = testSuiteConfig.getTestObject();

    return switch (testObjectConfig.getTestObjectType().getConnectionType()) {
      case TLS_SERVER -> TlsClientApplication.connectTls(
          testObjectConfig.getIpAddressOrFqdn(),
          testObjectConfig.getPort(),
          eeCertPath,
          PkitsTestDataConstants.KEYSTORE_PASSWORD,
          testSuiteConfig.getTestObject().getOcspTimeoutSeconds());
      case SCRIPT -> connectScript(eeCertPath, testSuiteConfig);
      case SCRIPT_OVER_SSH -> new SshUseCaseApplication(eeCertPath, testSuiteConfig).execute();
    };
  }

  private static int runProcessBuild(final ProcessBuilder processBuilder) {

    processBuilder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
    processBuilder.redirectError(ProcessBuilder.Redirect.INHERIT);

    try {
      final Process process = processBuilder.start();
      final boolean success = process.waitFor(30, TimeUnit.SECONDS);
      if (success) {
        return process.exitValue();
      }
      process.destroy();
      throw new TestSuiteException("Process timeout of 30 seconds.");
    } catch (final IOException e) {
      throw new TestSuiteException("Could not start process.", e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new TestSuiteException(e);
    }
  }

  private static void checkFile(final String filename) {
    if (filename == null || Files.notExists(Path.of(filename))) {
      throw new TestSuiteException("Error! Cannot read file: %s .".formatted(filename));
    }
  }

  private static int connectScript(final Path certPath, final TestSuiteConfig testSuiteConfig) {

    final String filename = testSuiteConfig.getTestObject().getScriptUseCase().getScriptPath();

    checkFile(filename);
    final ProcessBuilder processBuilder =
        new ProcessBuilder(
            filename,
            certPath.toString(),
            PkitsTestDataConstants.KEYSTORE_PASSWORD,
            String.valueOf(testSuiteConfig.getTestObject().getOcspTimeoutSeconds()));

    log.info("Run script {}", filename);
    return runProcessBuild(processBuilder);
  }
}
