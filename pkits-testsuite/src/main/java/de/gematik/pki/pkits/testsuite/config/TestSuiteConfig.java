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

package de.gematik.pki.pkits.testsuite.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import de.gematik.pki.pkits.common.PkiCommonException;
import java.io.IOException;
import java.nio.file.Path;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TestSuiteConfig {

  private ClientConfig client = new ClientConfig();

  private TestObjectConfig testObject = new TestObjectConfig();

  private SshConfig sshConfig = new SshConfig();

  private OcspResponderConfig ocspResponder = new OcspResponderConfig();

  private TslProviderConfig tslProvider = new TslProviderConfig();

  private TestSuiteParameter testSuiteParameter = new TestSuiteParameter();

  public static TestSuiteConfig fromYaml(final Path yamlFile) {
    final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    try {
      final TestSuiteConfig testSuiteConfig =
          yamlMapper.readValue(yamlFile.toFile(), TestSuiteConfig.class);

      if (testSuiteConfig.getOcspResponder() == null) {
        testSuiteConfig.setOcspResponder(new OcspResponderConfig());
      }

      if (testSuiteConfig.getTestSuiteParameter() == null) {
        testSuiteConfig.setTestSuiteParameter(new TestSuiteParameter());
      }

      if (testSuiteConfig.getTestSuiteParameter().getOcspSettings() == null) {
        testSuiteConfig.getTestSuiteParameter().setOcspSettings(new OcspSettings());
      }

      if (testSuiteConfig.getTestSuiteParameter().getTslSettings() == null) {
        testSuiteConfig.getTestSuiteParameter().setTslSettings(new TslSettings());
      }

      if (testSuiteConfig.getSshConfig() == null) {
        testSuiteConfig.setSshConfig(new SshConfig());
      }

      return testSuiteConfig;
    } catch (final IOException e) {
      throw new PkiCommonException("Cannot process yamlPath", e);
    }
  }
}
