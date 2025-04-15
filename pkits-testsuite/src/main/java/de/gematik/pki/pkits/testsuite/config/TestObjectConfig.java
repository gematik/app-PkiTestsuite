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

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TestObjectConfig {

  @ParameterDescription(
      description =
          "Name of the test object, for better identification in logs and configuration files.")
  String name;

  @ParameterDescription(
      description =
          "one of: IdpFachdienst, IntermediaerServer, KimFachdienst, VsdmFachdienst,"
              + " VpnKonzentrator, VpnRegServer")
  TestObjectType testObjectType;

  @ParameterDescription(description = "FQDN or IP address to connect to the test object.")
  String ipAddressOrFqdn;

  @ParameterDescription(description = "Port where the test object listens on.")
  int port;

  @ParameterDescription(
      withDefault = true,
      description = "OCSP grace period in seconds configured in the test object.")
  int ocspGracePeriodSeconds = 30;

  @ParameterDescription(
      withDefault = true,
      description =
          "OCSP tolerance for producedAt in the past, in seconds configured in the test object.")
  int ocspToleranceProducedAtPastSeconds = 5;

  @ParameterDescription(
      withDefault = true,
      description =
          "OCSP tolerance for producedAt in the future, in seconds configured in the test object.")
  int ocspToleranceProducedAtFutureSeconds = 3;

  @ParameterDescription(
      description = "TSL download interval in seconds configured in the test object.")
  int tslDownloadIntervalSeconds;

  @ParameterDescription(
      withDefault = true,
      description =
          "Duration in days after expiration of the TSL during which the TSL is still regarded as"
              + " valid.")
  int tslGracePeriodDays = 0;

  @ParameterDescription(
      withDefault = true,
      description =
          "Amount of seconds to wait after a TSL update for processing inside the test object.")
  int tslProcessingTimeSeconds = 3;

  @ParameterDescription(
      withDefault = true,
      description =
          "Amount of seconds to wait for OCSP requests to be processed by the test object and"
              + " corresponding network.")
  int ocspProcessingTimeSeconds = 1;

  @ParameterDescription(
      withDefault = true,
      description =
          "Amount of seconds after OCSP responses are not accepted by the test object anymore.")
  int ocspTimeoutSeconds = 10;

  ScriptUseCase scriptUseCase = new ScriptUseCase();
}
