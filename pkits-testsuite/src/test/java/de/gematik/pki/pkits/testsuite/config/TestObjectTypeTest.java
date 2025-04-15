/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.testsuite.config;

import static de.gematik.pki.pkits.testsuite.TestConstants.CONFIG_FILE_INTTEST_DIR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class TestObjectTypeTest {

  private static final ObjectMapper mapper = new ObjectMapper();

  @Test
  void readExistingConfigFiles() throws IOException {

    final List<Path> ymlFiles;
    try (final Stream<Path> ymlFilesStream = Files.list(CONFIG_FILE_INTTEST_DIR)) {
      ymlFiles = ymlFilesStream.filter(path -> path.toString().endsWith("yml")).toList();
    }

    assertThat(ymlFiles).hasSizeGreaterThanOrEqualTo(5);

    for (final Path ymlFile : ymlFiles) {
      assertDoesNotThrow(() -> TestSuiteConfig.fromYaml(ymlFile));
    }
  }

  @Test
  void testDeserialize() throws JsonProcessingException {
    final String testObjectConfigJsonStr =
        "{ 'testObjectType' : 'VsdmFachdienst' }".replace("'", "\"");

    final TestObjectConfig testObjectConfig =
        mapper.readValue(testObjectConfigJsonStr, TestObjectConfig.class);
    assertThat(testObjectConfig.getTestObjectType()).isEqualTo(TestObjectType.VSDM_FACHDIENST);
    assertThat(testObjectConfig.getTestObjectType().getTypeName()).isEqualTo("VsdmFachdienst");
    assertThat(testObjectConfig.getTestObjectType().getClientKeystorePathAlternativeCerts())
        .isEqualTo(
            Path.of("./testDataTemplates/certificates/ecc/intermediaerClient/valid-alternative"));
    assertThat(testObjectConfig.getTestObjectType().getClientKeystorePathRsaCerts())
        .isEqualTo(Path.of("./testDataTemplates/certificates/rsa/intermediaerClient"));
  }

  @Test
  void testDeserializeException() {
    final String testObjectConfigJsonStr = "{ 'testObjectType' : 'dummyValue' }".replace("'", "\"");

    assertThatThrownBy(() -> mapper.readValue(testObjectConfigJsonStr, TestObjectConfig.class))
        .isInstanceOf(ValueInstantiationException.class)
        .hasMessageStartingWith(
            "Cannot construct instance of `de.gematik.pki.pkits.testsuite.config.TestObjectType`,"
                + " problem: unknown value <dummyValue> for TestObjectType. Allowed values:"
                + " IdpEgkFachdienst, IdpFachdienst, IntermediaerServer, KimFachdienst,"
                + " VpnKonzentrator, VpnRegServer, VsdmFachdienst.");
  }

  @Test
  void testSerialize() throws JsonProcessingException {
    final String testObjectConfigJsonStr =
        "{ 'testObjectType' : 'VsdmFachdienst' }".replace("'", "\"");

    final TestObjectConfig testObjectConfig =
        mapper.readValue(testObjectConfigJsonStr, TestObjectConfig.class);
    assertThat(testObjectConfig.getTestObjectType()).isEqualTo(TestObjectType.VSDM_FACHDIENST);
  }
}
