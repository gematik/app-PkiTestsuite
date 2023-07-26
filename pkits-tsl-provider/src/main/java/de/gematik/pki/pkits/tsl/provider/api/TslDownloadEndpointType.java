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

package de.gematik.pki.pkits.tsl.provider.api;

import de.gematik.pki.pkits.common.PkitsConstants;
import lombok.Getter;

@Getter
public enum TslDownloadEndpointType {
  XML_ENDPOINTS(PkitsConstants.TSL_XML_PRIMARY_ENDPOINT, PkitsConstants.TSL_XML_BACKUP_ENDPOINT),
  HASH_ENDPOINTS(PkitsConstants.TSL_HASH_PRIMARY_ENDPOINT, PkitsConstants.TSL_HASH_BACKUP_ENDPOINT),
  ANY_ENDPOINT(
      PkitsConstants.TSL_XML_PRIMARY_ENDPOINT,
      PkitsConstants.TSL_XML_BACKUP_ENDPOINT,
      PkitsConstants.TSL_HASH_PRIMARY_ENDPOINT,
      PkitsConstants.TSL_HASH_BACKUP_ENDPOINT);
  private final String[] endpoints;

  TslDownloadEndpointType(final String... endpoints) {
    this.endpoints = endpoints;
  }
}
