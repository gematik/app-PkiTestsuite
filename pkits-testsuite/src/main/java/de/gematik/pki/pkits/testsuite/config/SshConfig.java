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

  @ParameterDescription(description = "TODO")
  String username;

  @ParameterDescription(description = "TODO")
  String password;

  @ParameterDescription(description = "TODO")
  String host;

  @ParameterDescription(withDefault = true, description = "TODO")
  @Default
  int port = 22;

  @ParameterDescription(description = "TODO")
  Path privateKey;

  @ParameterDescription(description = "TODO")
  String privateKeyPassphrase;

  // -------------------------------------------------------------

  @ParameterDescription(
      description =
          "send AppData over http-forwarder (to gematik OCSP-sim, as defined in bash script)")
  String appDataHttpFwdSocket;

  @ParameterDescription(withDefault = true, description = "RSA or ECC")
  @Default
  String cryptMethod = "ECC";

  // -------------------------------------------------------------
  @ParameterDescription(description = "TODO")
  Path filesToCopyRootDir;

  @ParameterDescription(
      description =
          "TODO see"
              + " https://docs.oracle.com/javase/8/docs/api/java/nio/file/FileSystem.html#getPathMatcher-java.lang.String-")
  String filesToCopyPattern;

  @ParameterDescription(description = "TODO")
  String remoteTargetDir;

  @ParameterDescription(description = "TODO")
  String remoteLogFile;

  @ParameterDescription(withDefault = true, description = "TODO")
  @Default
  long connectTimeoutSeconds = 4;

  @ParameterDescription(withDefault = true, description = "TODO")
  @Default
  long authTimeoutSeconds = 4;

  @ParameterDescription(withDefault = true, description = "TODO")
  @Default
  long channelOpenTimeoutSeconds = 4;

  @ParameterDescription(withDefault = true, description = "TODO")
  @Default
  long channelCloseTimeoutSeconds = 4;
}
