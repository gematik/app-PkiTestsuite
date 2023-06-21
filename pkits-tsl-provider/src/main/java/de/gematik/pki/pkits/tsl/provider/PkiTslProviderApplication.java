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

package de.gematik.pki.pkits.tsl.provider;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.Banner.Mode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.EventListener;

@Slf4j
@SpringBootApplication
public class PkiTslProviderApplication {
  private final ApplicationContext appContext;

  public PkiTslProviderApplication(final ApplicationContext appContext) {
    this.appContext = appContext;
  }

  @EventListener(ApplicationReadyEvent.class)
  public void init() {
    log.info("\n{}\n", PkitsCommonUtils.getBannerStr(PkiTslProviderApplication.class));
    final String serverPort = appContext.getEnvironment().getProperty("local.server.port");
    log.info("TslProvider started at port: {}", serverPort);
  }

  public static void main(final String[] args) {
    final SpringApplication app = new SpringApplication(PkiTslProviderApplication.class);
    app.setBannerMode(Mode.OFF);
    app.run(args);
  }
}