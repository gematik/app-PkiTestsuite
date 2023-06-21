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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.reporting.CurrentTestInfo;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class PersistTslOperation implements TslOperation {

  final CurrentTestInfo currentTestInfo;
  final String tslName;
  final Path tslFile;

  public PersistTslOperation(final CurrentTestInfo currentTestInfo, final String tslName) {
    this.currentTestInfo = currentTestInfo;
    this.tslName = tslName;
    this.tslFile = null;
  }

  public PersistTslOperation(final Path tslFile) {
    this.currentTestInfo = null;
    this.tslName = null;
    this.tslFile = tslFile;
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    final byte[] tslBytes = tslContainer.getAsTslBytes();
    final Path tslFileToUse;

    tslFileToUse =
        Objects.requireNonNullElseGet(
            tslFile,
            () ->
                PersistTslUtils.generateTslFilename(
                    currentTestInfo, tslName, tslContainer.getAsTsl()));

    try {
      if (Files.notExists(tslFileToUse.getParent())) {
        Files.createDirectories(tslFileToUse.getParent());
      }
      Files.write(tslFileToUse, tslBytes);
      log.info("saved TSL to file: {}", tslFileToUse);
    } catch (final IOException e) {
      throw new TestSuiteException("cannot save TSL to file", e);
    }
    return new TslContainer(tslBytes);
  }
}
