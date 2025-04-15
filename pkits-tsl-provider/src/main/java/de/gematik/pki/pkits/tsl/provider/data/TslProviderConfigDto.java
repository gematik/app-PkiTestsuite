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

package de.gematik.pki.pkits.tsl.provider.data;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.calculateSha256Hex;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
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
  private TslProviderEndpointsConfig tslProviderEndpointsConfig =
      TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200;

  @Override
  public String toString() {

    String tslInfo = "ignore: tslId and tslSeqNr: tsl - cannot be parsed";
    try {
      final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(tslBytes);
      tslInfo =
          "tslId: %s tslSeqNr: %s"
              .formatted(
                  tslUnsigned.getId(), tslUnsigned.getSchemeInformation().getTSLSequenceNumber());
    } catch (final Exception e) {
      log.debug(tslInfo, e);
    }

    return String.format(
        "tslDownloadPoint: tsl size: %d bytes, tsl hash: %s,  %s, tslProviderEndpointsConfig:"
            + " %s",
        tslBytes.length, calculateSha256Hex(tslBytes), tslInfo, tslProviderEndpointsConfig);
  }
}
