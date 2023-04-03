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

package de.gematik.pki.pkits.testsuite;

import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestObjectConfig;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.tls.client.TlsClientApplication;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class UseCase {

  private static final TestObjectConfig TEST_OBJECT_CONFIG =
      TestConfigManager.getTestSuiteConfig().getTestObject();

  public static int exec(final Path certPath) {

    return switch (TEST_OBJECT_CONFIG.getType()) {
      case "TlsServer" -> TlsClientApplication.connectTls(
          TEST_OBJECT_CONFIG.getIpAddressOrFqdn(),
          TEST_OBJECT_CONFIG.getPort(),
          certPath,
          TestConfigManager.getTestSuiteConfig().getClient().getKeystorePassword());
      case "Script" -> connectScript(
          certPath, TestConfigManager.getTestSuiteConfig().getClient().getKeystorePassword());
      default -> throw new TestSuiteException("Unknown test object type.");
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
      throw new RuntimeException(e);
    }
  }

  private static void checkFile(final String filename) {
    if (filename == null || !Files.exists(Path.of(filename))) {
      throw new TestSuiteException("Error! Cannot read file: %s .".formatted(filename));
    }
  }

  private static int connectScript(final Path certPath, final String password) {

    final String filename = TEST_OBJECT_CONFIG.getScriptPath();

    checkFile(filename);
    final ProcessBuilder processBuilder =
        new ProcessBuilder(filename, certPath.toString(), password);

    log.info("Run script {}", TEST_OBJECT_CONFIG.getScriptPath());
    return runProcessBuild(processBuilder);
  }
}
