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

package de.gematik.pki.pkits.testsuite.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TestObjectConfig {

  @ParameterDescription(
      description =
          "Name of the test object, for better identification in logs and configuration files.")
  String name;

  @ParameterDescription(description = "Test object type (TlsServer|Script).")
  String type;

  @ParameterDescription(description = "FQDN or IP address to connect to the test object.")
  String ipAddressOrFqdn;

  @ParameterDescription(description = "Port where the test object listens on.")
  @Setter
  int port;

  @ParameterDescription(
      withDefault = true,
      description =
          "Absolute or relative path to the use case script when test object type is set to"
              + " 'Script'.")
  String scriptPath = "unused by default";

  @ParameterDescription(
      withDefault = true,
      description = "OCSP grace period in seconds configured in the test object.")
  int ocspGracePeriodSeconds = 30;

  @ParameterDescription(
      description = "TSL download interval in seconds configured in the test object.")
  int tslDownloadIntervalSeconds;

  @ParameterDescription(
      withDefault = true,
      description =
          "Amount of seconds to wait after a TSL update for processing inside the test object.")
  int tslProcessingTimeSeconds = 3;

  @ParameterDescription(
      withDefault = true,
      description =
          "Amount of seconds after OCSP responses are not accepted by the test object anymore.")
  int ocspTimeoutSeconds = 10;
}
