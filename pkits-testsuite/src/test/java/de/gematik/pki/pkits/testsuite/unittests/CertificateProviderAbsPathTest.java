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

package de.gematik.pki.pkits.testsuite.unittests;

import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.PKITS_CERT.PKITS_CERT_INVALID;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.PKITS_CERT.PKITS_CERT_VALID;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.PKITS_CFG_FILE_PATH;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.pkits.testsuite.common.CertificateProvider;
import de.gematik.pki.pkits.testsuite.common.VariableSource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/**
 * CertificateProvider reads config file which contains relative paths. Therefore, before all tests,
 * the config file must be edited in order to use absolute paths.
 */
@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertificateProviderAbsPathTest {

  static final Path configFileInttestTemplatePath = Path.of("./docs/configs/inttest/pkits.yml");

  @BeforeAll
  public void setup() throws IOException {
    createConfigFileWithAbsolutePathsToCerts();
  }

  @AfterAll
  static void tearDown() throws IOException {
    // restore config file (maven might have copied it)
    Files.copy(
        configFileInttestTemplatePath, PKITS_CFG_FILE_PATH, StandardCopyOption.REPLACE_EXISTING);
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_VALID)
  void testAbsPathArgumentsSourceValidCerts(final Path certPath) {
    log.info("\n\n Test with certificate \"{}\"\n", certPath);
    assertThat(certPath.toString()).contains(".p12");
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_INVALID)
  void testAbsPathArgumentsSourceInvalidCerts(final Path certPath) {
    log.info("\n\n Test with certificate \"{}\"\n", certPath);
    assertThat(certPath.toString()).contains(".p12");
  }

  private void createConfigFileWithAbsolutePathsToCerts() throws IOException {
    final Path configFilePathSrc = Path.of("./docs/configs/inttest/pkits.yml");

    final String validCertRsaPath =
        Path.of("../testDataTemplates/certificates/rsa/valid").toString().replace("\\", "/");
    final String invalidCertRsaPath =
        Path.of("../testDataTemplates/certificates/rsa/invalid").toString().replace("\\", "/");

    String fileContent = Files.readString(configFilePathSrc);

    fileContent =
        fileContent.replace(
            "keystorePathValidCerts: \"src/test/resources/certificates/rsa/valid\"",
            "keystorePathValidCerts: \"" + validCertRsaPath + "\"");
    fileContent =
        fileContent.replace(
            "keystorePathInvalidCerts: \"src/test/resources/certificates/rsa/invalid\"",
            "keystorePathInvalidCerts: \"" + invalidCertRsaPath + "\"");

    Files.writeString(PKITS_CFG_FILE_PATH, fileContent);
  }
}
