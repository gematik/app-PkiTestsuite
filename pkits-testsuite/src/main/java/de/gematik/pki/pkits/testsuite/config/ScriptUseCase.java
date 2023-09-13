/*
 * Copyright 2023 gematik GmbH
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
import lombok.Setter;

@Getter
@Setter
public class ScriptUseCase {
  @ParameterDescription(
      withDefault = true,
      description =
          "Absolute or relative path to the use case script when test object type is set to"
              + " 'Script'.")
  String scriptPath = "unused by default";

  @ParameterDescription(
      withDefault = true,
      description = "Parameter can be used to differentiate code inside a script")
  boolean sendReceiveApplicationData = true;

  @ParameterDescription(
      description =
          "send AppData over http-forwarder (to gematik OCSP-sim, as defined in bash script)")
  String appDataHttpFwdSocket;

  @ParameterDescription(
      withDefault = true,
      description =
          "Parameter is used as an argument for the called script. It can be used for handling"
              + " different implementations in RSA or ECC.")
  String cryptMethod = "ECC";
}
