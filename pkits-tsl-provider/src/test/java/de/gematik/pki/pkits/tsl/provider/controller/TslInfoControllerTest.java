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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.pkits.common.JsonTransceiver;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.common.TslConfigurator;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto;
import de.gematik.pki.pkits.tsl.provider.data.TslInfoRequestDto.HistoryDeleteOption;
import java.nio.charset.StandardCharsets;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.apache.http.HttpStatus;
import org.assertj.core.api.Assertions;
import org.json.JSONArray;
import org.json.JSONException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TslInfoControllerTest {

  String tslInfoUrl;
  String tslServiceUrlPrimary;
  String tslServiceUrlBackup;
  @LocalServerPort private int localServerPort;
  @Autowired private TslConfigHolder tslConfigHolder;

  /** TslProvider has already started. */
  @BeforeAll
  void init() {
    tslInfoUrl = "http://localhost:" + localServerPort + PkitsConstants.TSL_WEBSERVER_INFO_ENDPOINT;
    tslServiceUrlPrimary = "http://localhost:" + localServerPort + TSL_XML_PRIMARY_ENDPOINT;
    tslServiceUrlBackup = "http://localhost:" + localServerPort + TSL_XML_BACKUP_ENDPOINT;
  }

  @BeforeEach
  public void before() {
    invalidateTslConfiguration();
  }

  /**
   * Get full TslRequestHistory. Send a few requests with different sequenceNr. History should
   * contain these requests. Expected is a JSONArray of exact size. Clean history.
   */
  @Test
  void getFullTslRequestHistoryAsJson() throws JSONException {
    TslConfigurator.configureTsl(
        localServerPort,
        "dummy tsl content".getBytes(StandardCharsets.UTF_8),
        TSL_DOWNLOAD_POINT_PRIMARY);
    final int REQUEST_AMOUNT = 4;
    for (int i = 0; i < REQUEST_AMOUNT; i++) {
      sendTslDownloadRequest(i);
    }
    // IGNORE_SEQUENCE_NUMBER == FULL_HISTORY_IS_REQUESTED
    final JSONArray jsonArray = getHistoryAndClear(IGNORE_SEQUENCE_NUMBER);

    assertThat(jsonArray.length()).isEqualTo(REQUEST_AMOUNT);
  }

  /**
   * Get TslRequestHistory for a sequenceNr. Send a few requests with same sequenceNr. History
   * should contain these requests. Expected is a JSONArray of exact size. Clean history for this
   * sequenceNr.
   */
  @Test
  void getTslRequestHistoryAsJsonForSequenceNr() throws JSONException {
    TslConfigurator.configureTsl(
        localServerPort,
        "dummy tsl content".getBytes(StandardCharsets.UTF_8),
        TSL_DOWNLOAD_POINT_PRIMARY);
    final int SEQ_NR = 2;
    final int REQUEST_AMOUNT = 4;
    for (int i = 0; i < REQUEST_AMOUNT; i++) {
      sendTslDownloadRequest(SEQ_NR);
    }

    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(SEQ_NR, HistoryDeleteOption.DELETE_SEQNR_ENTRY);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(tslInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(tslInfoUrl, requestBodyAsJson);
    final JSONArray jsonArray = new JSONArray(responseBodyAsJson);

    assertThat(jsonArray.length()).isEqualTo(REQUEST_AMOUNT);
  }

  /**
   * Get empty TslRequestHistory. Send a request with imaginary sequenceNr. History should be empty.
   * Expected is a String that represents an empty array.
   */
  @Test
  void getEmptyTslRequestHistoryForImaginarySequenceNrAsJson() {
    final int sequenceNr = 4711;
    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(sequenceNr, HistoryDeleteOption.DELETE_NOTHING);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(tslInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(tslInfoUrl, requestBodyAsJson);
    assertThat(responseBodyAsJson).isEqualTo("[]");
  }

  /**
   * Send a few requests with different sequenceNr, delete full history via InfoRequest with used
   * sequenceNr. Check via InfoRequest with other used sequenceNr if history is clear.
   */
  @Test
  void deleteCompleteTslRequestHistory() throws JSONException {
    TslConfigurator.configureTsl(
        localServerPort,
        "dummy tsl content".getBytes(StandardCharsets.UTF_8),
        TSL_DOWNLOAD_POINT_PRIMARY);
    final int REQUEST_AMOUNT = 25;
    for (int i = 0; i < REQUEST_AMOUNT; i++) {
      sendTslDownloadRequest(i);
    }

    final int usedSeqNr = 18;
    // make sure that seqNr was in request loop
    assertThat(usedSeqNr).isLessThan(REQUEST_AMOUNT);
    final JSONArray jsonArray1 = getHistoryAndClear(usedSeqNr);
    assertThat(jsonArray1.length()).isEqualTo(1);

    final int otherUsedSeqNr = 22;
    // make sure that seqNr was in request loop
    assertThat(otherUsedSeqNr).isLessThan(REQUEST_AMOUNT);
    final JSONArray jsonArray2 = getHistoryAndClear(otherUsedSeqNr);
    assertThat(jsonArray2.length()).isZero();
  }

  private JSONArray getHistoryAndClear(final int seqNr) throws JSONException {
    final TslInfoRequestDto tslInfoRequest =
        new TslInfoRequestDto(seqNr, HistoryDeleteOption.DELETE_FULL_HISTORY);
    final String requestBodyAsJson = PkitsCommonUtils.createJsonContent(tslInfoRequest);
    final String responseBodyAsJson =
        JsonTransceiver.txRxJsonViaHttp(tslInfoUrl, requestBodyAsJson);
    return new JSONArray(responseBodyAsJson);
  }

  private void sendTslDownloadRequest(final int seqNr) throws UnirestException {
    final HttpResponse<byte[]> response =
        Unirest.get(tslServiceUrlPrimary).queryString(TSL_SEQNR_PARAM_ENDPOINT, seqNr).asBytes();
    Assertions.assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
  }

  private void invalidateTslConfiguration() {
    tslConfigHolder.setTslProviderConfigDto(null);
  }
}
