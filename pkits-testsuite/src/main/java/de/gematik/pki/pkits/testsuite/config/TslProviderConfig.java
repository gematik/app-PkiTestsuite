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

import lombok.Getter;

@Getter
public class TslProviderConfig {

  @ParameterDescription(
      description =
          "FQDN or IP address where the tsl provider is running. This will be used as the"
              + " PointersToOther field in the TSLs.")
  String ipAddressOrFqdn;

  @ParameterDescription(description = "Port where the TSL provider is listening.")
  int port;

  @ParameterDescription(
      withDefault = true,
      description = "Name of the TSL provider for better identification in log files.")
  String id = "TSL Provider";

  @ParameterDescription(
      withDefault = true,
      description =
          "Path to the TSL provider jar which should be started during tests. This can be skipped"
              + " with the keyword \"externalStartup\".")
  String appPath = "./bin/pkits-tsl-provider-exec.jar";
}
