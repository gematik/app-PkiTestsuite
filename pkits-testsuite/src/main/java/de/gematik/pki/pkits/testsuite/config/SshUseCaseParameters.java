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

package de.gematik.pki.pkits.testsuite.config;

import java.nio.file.Path;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SshUseCaseParameters {

  @ParameterDescription(
      description = "Directory containing files, that should be copied to the remote SSH machine.")
  Path filesToCopyRootDir;

  @ParameterDescription(
      description =
          "Wildcard filter for selecting files from the 'filesToCopyRootDir'. See"
              + " https://docs.oracle.com/javase/8/docs/api/java/nio/file/FileSystem.html#getPathMatcher-java.lang.String-")
  String filesToCopyPattern;

  @ParameterDescription(
      description = "Target directory on the SSH remote machine, where files are copied to.")
  String remoteTargetDir;

  @ParameterDescription(
      description =
          "Filename of a log file on the remote SSH machine. This file is copied back from the"
              + " remote machine.")
  String remoteLogFile;
}
