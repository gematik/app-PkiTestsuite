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

package de.gematik.pki.pkits.tls.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.ResourceReader;
import java.io.IOException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
public final class PluginConfig {

  TlsSettings tlsSettings;
  private static PluginConfig instance;

  public static PluginConfig getInstance() {
    if (instance == null) {

      final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
      try {
        final String cfgFile = ResourceReader.getFileFromResourceAsString("application.yml");
        instance = yamlMapper.readValue(cfgFile, PluginConfig.class);
      } catch (final IOException e) {
        throw new PkiCommonException("Cannot process yamlPath", e);
      }
    }
    return instance;
  }
}
