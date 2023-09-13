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

package de.gematik.pki.pkits.tsl.provider.data;

import lombok.Getter;

@Getter
public enum TslProviderEndpointsConfig {
  PRIMARY_200_BACKUP_200(200, 200),
  PRIMARY_200_BACKUP_404(200, 404),
  PRIMARY_404_BACKUP_200(404, 200),
  PRIMARY_404_BACKUP_404(404, 404);

  private final int primaryStatusCode;
  private final int backupStatusCode;

  TslProviderEndpointsConfig(final int primaryStatusCode, final int backupStatusCode) {
    this.primaryStatusCode = primaryStatusCode;
    this.backupStatusCode = backupStatusCode;
  }
}
