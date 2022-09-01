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

package de.gematik.pki.pkits.ocsp.responder.api;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_BEARER_TOKEN;
import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_CONFIG_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_INFO_ENDPOINT;

import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.data.OcspConfigRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspInfoRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspResponderManager {

  public static void configure(final String uri, final OcspResponderConfigDto ocspResponderConfig) {
    final String configUri = uri + WEBSERVER_CONFIG_ENDPOINT;
    final OcspConfigRequestDto configReq =
        new OcspConfigRequestDto(WEBSERVER_BEARER_TOKEN, ocspResponderConfig);
    final String jsonContent =
        PkitsCommonUtils.createJsonContent(PkitsCommonUtils.objectToBytes(configReq));
    // received by {@link class OcspConfigController}
    JsonTransceiver.sendJsonViaHttp(configUri, jsonContent);
  }

  /**
   * Get the history of OcspRequests for given certificate serial number.
   *
   * @param uri OcspResponder URI
   * @param certSerialNr certificate serial number
   * @return all entries belonging to given certificate serial number as part of the history
   */
  public static List<OcspRequestHistoryEntryDto> getOcspHistoryPart(
      final String uri, final BigInteger certSerialNr) {
    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(certSerialNr, OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
    return sendInfoRequest(uri, ocspInfoRequest);
  }

  /**
   * Get and clear the history of OcspRequests for given certificate serial number.
   *
   * @param uri OcspResponder URI
   * @param certSerialNr certificate serial number
   * @return all entries belonging to given certificate serial number as part of the history
   */
  public static List<OcspRequestHistoryEntryDto> getAndClearOcspHistoryPart(
      final String uri, final BigInteger certSerialNr) {
    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            certSerialNr, OcspInfoRequestDto.HistoryDeleteOption.DELETE_CERT_HISTORY);
    return sendInfoRequest(uri, ocspInfoRequest);
  }

  /**
   * Clear the complete history of OcspRequests.
   *
   * @param uri OcspResponder URI
   */
  public static void clearOcspHistory(final String uri) {
    final BigInteger invalidCertSerialNr = BigInteger.valueOf(-1);
    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            invalidCertSerialNr, OcspInfoRequestDto.HistoryDeleteOption.DELETE_FULL_HISTORY);
    sendInfoRequest(uri, ocspInfoRequest);
  }

  private static List<OcspRequestHistoryEntryDto> sendInfoRequest(
      final String uri, final OcspInfoRequestDto ocspInfoRequestDto) {
    final String jsonContent = PkitsCommonUtils.createJsonContent(ocspInfoRequestDto);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(uri + WEBSERVER_INFO_ENDPOINT, jsonContent);
    log.debug("JsonTransceiver, responseBodyAsJson: {}", responseBodyAsJson);
    if (responseBodyAsJson.isEmpty()) {
      return Collections.emptyList();
    }
    return PkitsCommonUtils.convertToList(responseBodyAsJson, OcspRequestHistoryEntryDto.class);
  }
}
