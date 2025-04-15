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

package de.gematik.pki.pkits.tsl.provider;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import jakarta.annotation.PreDestroy;
import java.util.Properties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.Banner.Mode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.EventListener;

@Slf4j
@AllArgsConstructor
@SpringBootApplication
public class PkiTslProviderApplication {
  private final ApplicationContext appContext;

  @EventListener(ApplicationReadyEvent.class)
  public void init() {
    log.info(
        "\n{}\n",
        PkitsCommonUtils.getBannerStr(
            PkiTslProviderApplication.class, "bannerFormatTslProvider.txt"));
    final String serverPort = appContext.getEnvironment().getProperty("local.server.port");
    log.info("TslProvider started at port: {}", serverPort);
  }

  @PreDestroy
  public void onDestroy() {
    log.info("PkiTslProviderApplication is destroyed!");
  }

  public static void main(final String[] args) {
    final Properties props = new Properties();
    props.put("spring.config.name", "application-tsl-provider");
    final SpringApplication app = new SpringApplication(PkiTslProviderApplication.class);
    app.setBannerMode(Mode.OFF);
    app.setDefaultProperties(props);
    app.run(args);
  }
}
