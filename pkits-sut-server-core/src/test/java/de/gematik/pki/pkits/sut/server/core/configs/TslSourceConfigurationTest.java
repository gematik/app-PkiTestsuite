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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.sut.server.core.tsl.DefaultTslSource;
import de.gematik.pki.pkits.sut.server.core.tsl.InternetTslSource;
import de.gematik.pki.pkits.sut.server.core.tsl.TslSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

class TslSourceConfigurationTest {

  private final ApplicationContextRunner applicationContextRunner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class))
          .withUserConfiguration(TestConfiguration.class)
          .withPropertyValues(
              "tsl-procurer.initial-tsl-download-url=http://localhost:8084/tsl/tsl.xml?activeTslSeqNr=0",
              "tsl-procurer.download-interval=2",
              "tsl-procurer.repetitions=4",
              "tsl-procurer.tsl-grace-period-days=0",
              "tsl-procurer.timeout-milliseconds=500");

  @Test
  void shouldUseLocalTslSourceByDefault() {
    applicationContextRunner.run(
        context -> {
          assertThat(context).hasSingleBean(TslSource.class);
          assertThat(context.getBean(TslSource.class)).isInstanceOf(DefaultTslSource.class);
        });
  }

  @Test
  void shouldUseLocalTslSourceWhenConfigured() {
    applicationContextRunner
        .withPropertyValues("tsl-procurer.source=local")
        .run(
            context -> {
              assertThat(context).hasSingleBean(TslSource.class);
              assertThat(context.getBean(TslSource.class)).isInstanceOf(DefaultTslSource.class);
            });
  }

  @Test
  void shouldUseInternetTslSourceWhenConfigured() {
    applicationContextRunner
        .withPropertyValues("tsl-procurer.source=internet")
        .run(
            context -> {
              assertThat(context).hasSingleBean(TslSource.class);
              assertThat(context.getBean(TslSource.class)).isInstanceOf(InternetTslSource.class);
            });
  }

  @Configuration
  @EnableConfigurationProperties(TslProcurerProperties.class)
  @Import(TslSourceConfiguration.class)
  static class TestConfiguration {}
}
