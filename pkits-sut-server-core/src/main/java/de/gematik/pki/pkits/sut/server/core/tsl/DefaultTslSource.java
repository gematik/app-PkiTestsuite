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

package de.gematik.pki.pkits.sut.server.core.tsl;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.tsl.TslReader;
import de.gematik.pki.pkits.sut.server.core.configs.TslConfig;
import de.gematik.pki.pkits.sut.server.core.configs.TslProcurerProperties;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DefaultTslSource extends AbstractTslSource {

  public DefaultTslSource(final TslProcurerProperties tslProcurerProperties) {
    super(tslProcurerProperties);
  }

  @Override
  public String getInitialTslUrl() {
    return TslConfig.buildTslDownloadUrl(tslProcurerProperties.getInitialTslDownloadUrl());
  }

  @Override
  public Optional<String> getPrimaryTslUrl(final Tsl currentTsl) {
    try {
      return Optional.of(TslReader.getTslDownloadUrlPrimary(currentTsl.tslUnsigned));
    } catch (final GemPkiRuntimeException e) {
      log.warn("cannot extract primary tsl url: {}", e.getMessage());
      return Optional.empty();
    }
  }

  @Override
  public Optional<String> getBackupTslUrl(final Tsl currentTsl) {
    try {
      return Optional.of(TslReader.getTslDownloadUrlBackup(currentTsl.tslUnsigned));
    } catch (final GemPkiRuntimeException e) {
      log.warn("cannot extract backup tsl url: {}", e.getMessage());
      return Optional.empty();
    }
  }
}
