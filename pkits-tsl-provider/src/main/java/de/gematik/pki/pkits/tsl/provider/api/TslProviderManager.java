/*
 * Copyright (c) 2022 gematik GmbH
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

package de.gematik.pki.pkits.tsl.provider.api;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_BEARER_TOKEN;
import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_INFO_ENDPOINT;

import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.tsl.provider.data.TslConfigRequestDto;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto.HistoryDeleteOption;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.util.Collections;
import java.util.List;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslProviderManager {

  public static void clearTslHistory(final String tslProvUri) {
    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(0, HistoryDeleteOption.DELETE_FULL_HISTORY);
    sendInfoRequest(tslProvUri, tslInfoRequest);
  }

  public static void configure(final String uri, final TslProviderConfigDto tslProviderConfigDto) {
    final String configUri = uri + WEBSERVER_CONFIG_ENDPOINT;
    final TslConfigRequestDto configReq =
        new TslConfigRequestDto(WEBSERVER_BEARER_TOKEN, tslProviderConfigDto);
    final String jsonContent = PkitsCommonUtils.createJsonContent(configReq);
    JsonTransceiver.sendJsonViaHttp(configUri, jsonContent);
  }

  public static List<TslRequestHistoryEntryDto> getTslRequestHistoryPart(
      final String uri, final int sequenceNr) {
    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(sequenceNr, HistoryDeleteOption.DELETE_NOTHING);
    return sendInfoRequest(uri, tslInfoRequest);
  }

  private static List<TslRequestHistoryEntryDto> sendInfoRequest(
      final String uri, final TslInfoRequestDto tslInfoRequestDto) {
    final String jsonContent = PkitsCommonUtils.createJsonContent(tslInfoRequestDto);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(uri + WEBSERVER_INFO_ENDPOINT, jsonContent);
    log.debug("JsonTransceiver, responseBodyAsJson: {}", responseBodyAsJson);
    if (responseBodyAsJson.isEmpty()) {
      return Collections.emptyList();
    }

    return PkitsCommonUtils.convertToList(responseBodyAsJson, TslRequestHistoryEntryDto.class);
  }
}
