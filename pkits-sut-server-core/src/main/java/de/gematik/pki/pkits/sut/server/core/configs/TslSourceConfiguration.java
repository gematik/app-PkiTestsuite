/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.sut.server.core.configs;

import de.gematik.pki.pkits.sut.server.core.tsl.DefaultTslSource;
import de.gematik.pki.pkits.sut.server.core.tsl.InternetTslSource;
import de.gematik.pki.pkits.sut.server.core.tsl.TslSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TslSourceConfiguration {

  @Bean
  @ConditionalOnProperty(
      prefix = "tsl-procurer",
      name = "source",
      havingValue = "local",
      matchIfMissing = true)
  TslSource localTslSource(final TslProcurerProperties tslProcurerProperties) {
    return new DefaultTslSource(tslProcurerProperties);
  }

  @Bean
  @ConditionalOnProperty(prefix = "tsl-procurer", name = "source", havingValue = "internet")
  TslSource internetTslSource(final TslProcurerProperties tslProcurerProperties) {
    return new InternetTslSource(tslProcurerProperties);
  }
}
