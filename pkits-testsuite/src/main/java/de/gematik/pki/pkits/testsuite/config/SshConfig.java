/*
 * Copyright (Date see Readme), gematik GmbH
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

import java.nio.file.Path;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SshConfig {

  @ParameterDescription(description = "Username for the SSH login")
  String username;

  @ParameterDescription(description = "Passwort in case of password based authentication.")
  String password;

  @ParameterDescription(description = "IP address to connect to via SSH.")
  String host;

  @ParameterDescription(withDefault = true, description = "Port for the SSH connect.")
  @Default
  int port = 22;

  @ParameterDescription(description = "Private key in case of key based authentication.")
  Path privateKey;

  @ParameterDescription(
      description = "Password for the private key in case of key based authentication.")
  String privateKeyPassphrase;

  @ParameterDescription(withDefault = true, description = "Timeout for the SSH session.")
  @Default
  long connectTimeoutSeconds = 60;

  @ParameterDescription(
      withDefault = true,
      description =
          "Timeout for the verification phase during the session connection establishment.")
  @Default
  long authTimeoutSeconds = 60;

  @ParameterDescription(withDefault = true, description = "Timeout during channel establishment.")
  @Default
  long channelOpenTimeoutSeconds = 60;

  @ParameterDescription(withDefault = true, description = "Timeout during SSH channel.")
  @Default
  long channelCloseTimeoutSeconds = 60;

  @Default private SshUseCaseParameters sshUseCaseParameters = new SshUseCaseParameters();
}
