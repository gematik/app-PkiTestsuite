/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.pkits.tsl.provider.data;

import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Slf4j
public class TslProviderConfigDto {

  private byte[] tslBytes;
  private TslDownloadPoint activeTslDownloadPoint;
  private TslProviderEndpointsConfig tslProviderEndpointsConfig =
      TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200;

  @Getter
  public enum TslProviderEndpointsConfig {
    PRIMARY_200_BACKUP_200(200, 200),
    PRIMARY_200_BACKUP_404(200, 404),
    PRIMARY_404_BACKUP_200(404, 200),
    PRIMARY_404_BACKUP_404(404, 404);

    int primaryStatusCode;
    int backupStatusCode;

    TslProviderEndpointsConfig(final int primaryStatusCode, final int backupStatusCode) {
      this.primaryStatusCode = primaryStatusCode;
      this.backupStatusCode = backupStatusCode;
    }
  }

  @Override
  public String toString() {
    final Object message;
    if (activeTslDownloadPoint != null) {
      message = activeTslDownloadPoint.name();
    } else {
      message = NOT_CONFIGURED;
    }

    String tslInfo = "ignore: tslId and seqNr: tsl - cannot be parsed";
    try {
      final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);
      tslInfo =
          "tslId: " + tsl.getId() + " seqNr: " + tsl.getSchemeInformation().getTSLSequenceNumber();
    } catch (final Exception e) {
      log.debug(tslInfo, e);
    }

    return String.format(
        "tslDownloadPoint: %s, tsl size: %d bytes, %s, tslProviderEndpointsConfig: %s",
        message, tslBytes.length, tslInfo, tslProviderEndpointsConfig);
  }
}
