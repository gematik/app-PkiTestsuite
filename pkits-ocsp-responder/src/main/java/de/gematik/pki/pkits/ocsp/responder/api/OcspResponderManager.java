/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.ocsp.responder.api;

import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.ocsp.responder.data.OcspInfoRequestDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspResponderManager {

  public static final int IGNORE_SEQUENCE_NUMBER = -1;
  public static final BigInteger IGNORE_CERT_SERIAL_NUMBER = BigInteger.valueOf(-1);

  public static void configure(
      final String ocspRespUri, final OcspResponderConfig ocspResponderConfig) {

    final String jsonContent = PkitsCommonUtils.createJsonContent(ocspResponderConfig.toJsonDto());

    PkitsCommonUtils.checkHealth(log, "OcspResponder", ocspRespUri);

    /**
     * received by {@link
     * de.gematik.pki.pkits.ocsp.responder.controllers.OcspConfigController#ocspConfig}
     */
    JsonTransceiver.sendJsonViaHttp(
        ocspRespUri + PkitsConstants.OCSP_WEBSERVER_CONFIG_ENDPOINT, jsonContent);
  }

  public static void clear(final String uri) {
    JsonTransceiver.deleteViaHttp(uri + PkitsConstants.OCSP_WEBSERVER_CLEAR_ENDPOINT, true);
  }

  /**
   * Get the history of OcspRequests for given certificate serial number.
   *
   * @param uri OcspResponder URI
   * @param tslSeqNr TSL sequence number
   * @param certSerialNr certificate serial number
   * @return all entries belonging to given certificate serial number as part of the history
   */
  public static List<OcspRequestHistoryEntryDto> getOcspHistoryPart(
      final String uri, final Integer tslSeqNr, final BigInteger certSerialNr) {
    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            tslSeqNr, certSerialNr, OcspInfoRequestDto.HistoryDeleteOption.DELETE_NOTHING);
    return sendInfoRequest(uri, ocspInfoRequest);
  }

  /**
   * Get and clear the history of OcspRequests for given certificate serial number.
   *
   * @param uri OcspResponder URI
   * @param tslSeqNr TSL sequence number
   * @param certSerialNr certificate serial number
   * @return all entries belonging to given certificate serial number as part of the history
   */
  public static List<OcspRequestHistoryEntryDto> getAndClearOcspHistoryPart(
      final String uri, final Integer tslSeqNr, final BigInteger certSerialNr) {
    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            tslSeqNr, certSerialNr, OcspInfoRequestDto.HistoryDeleteOption.DELETE_QUERIED_HISTORY);
    return sendInfoRequest(uri, ocspInfoRequest);
  }

  /**
   * Clear the complete history of OcspRequests.
   *
   * @param uri OcspResponder URI
   */
  public static void clearOcspHistory(final String uri) {

    final OcspInfoRequestDto ocspInfoRequest =
        new OcspInfoRequestDto(
            IGNORE_SEQUENCE_NUMBER,
            IGNORE_CERT_SERIAL_NUMBER,
            OcspInfoRequestDto.HistoryDeleteOption.DELETE_FULL_HISTORY);

    sendInfoRequest(uri, ocspInfoRequest);
    log.info(
        "OcspHistory cleared, at {} for tslSeqNr {} and certSerialNr {}",
        uri,
        IGNORE_SEQUENCE_NUMBER,
        IGNORE_CERT_SERIAL_NUMBER);
  }

  private static List<OcspRequestHistoryEntryDto> sendInfoRequest(
      final String uri, final OcspInfoRequestDto ocspInfoRequestDto) {

    final String jsonContent = PkitsCommonUtils.createJsonContent(ocspInfoRequestDto);

    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(
            uri + PkitsConstants.OCSP_WEBSERVER_INFO_ENDPOINT, jsonContent);

    log.debug("JsonTransceiver, responseBodyAsJson: {}", responseBodyAsJson);
    if (responseBodyAsJson.isEmpty()) {
      return Collections.emptyList();
    }
    return PkitsCommonUtils.convertToList(responseBodyAsJson, OcspRequestHistoryEntryDto.class);
  }
}
