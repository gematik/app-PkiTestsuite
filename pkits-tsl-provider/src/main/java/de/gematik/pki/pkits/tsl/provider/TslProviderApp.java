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

package de.gematik.pki.pkits.tsl.provider;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_BEARER_TOKEN;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.EventListener;

@Slf4j
@SpringBootApplication
public class TslProviderApp {

  private final TslConfigHolder tslConfigHolder;
  private final ApplicationContext appContext;

  @Autowired
  public TslProviderApp(
      final TslConfigHolder tslConfigHolder, final ApplicationContext appContext) {
    this.tslConfigHolder = tslConfigHolder;
    this.appContext = appContext;
  }

  // https://rules.sonarsource.com/java/RSPEC-4823 "This rule is deprecated, and will eventually
  // be removed."
  @SuppressWarnings("java:S4823")
  public static void main(final String[] args) {
    SpringApplication.run(TslProviderApp.class, args);
  }

  @EventListener(ApplicationReadyEvent.class)
  public void init() {
    tslConfigHolder.setBearerToken(WEBSERVER_BEARER_TOKEN);
    log.info(
        "TslProvider started at port: {}",
        appContext.getEnvironment().getProperty("local.server.port"));
  }
}
