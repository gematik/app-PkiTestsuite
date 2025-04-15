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

package de.gematik.pki.pkits.ocsp.responder.api;

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_REQUEST;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.MEDIA_TYPE_APPLICATION_OCSP_RESPONSE;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static de.gematik.pki.pkits.ocsp.responder.controllers.OcspResponderTestUtils.getEntry;
import static org.apache.hc.core5.http.HttpHeaders.ACCEPT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import java.math.BigInteger;
import java.util.List;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
@Slf4j
class OcspResponderManagerTest {

  @LocalServerPort private int localServerPort;
  @Autowired OcspRequestHistory ocspRequestHistory;

  private String ocspRespUri;

  @BeforeEach
  void setup() {
    ocspRespUri = "http://localhost:" + localServerPort;
  }

  @Test
  void testCheckHealthOk() {
    PkitsCommonUtils.checkHealth(log, "OcspResponder", ocspRespUri);
  }

  @Test
  void testCheckHealthException() {
    final String badOcspRespUri = "http://localhostX:" + localServerPort;
    Assertions.assertThatThrownBy(
            () -> PkitsCommonUtils.checkHealth(log, "OcspResponder", badOcspRespUri))
        .isInstanceOf(PkiCommonException.class)
        .hasMessageContaining("OcspResponder has health problem");
  }

  private void assertGetOcspHistoryPart(
      final Integer tslSeqNr, final String certSerialNrStr, final int expectedAmount) {

    BigInteger certSerialNr = null;

    if (certSerialNrStr != null) {
      certSerialNr = new BigInteger(certSerialNrStr);
    }

    final List<OcspRequestHistoryEntryDto> entries =
        OcspResponderManager.getOcspHistoryPart(ocspRespUri, tslSeqNr, certSerialNr);

    assertThat(entries).hasSize(expectedAmount);
  }

  @Test
  void testGetOcspHistoryPart() {

    OcspResponderManager.clearOcspHistory(ocspRespUri);

    ocspRequestHistory.add(getEntry(1, "10001"));

    ocspRequestHistory.add(getEntry(2, "10001"));
    ocspRequestHistory.add(getEntry(2, "10001"));

    ocspRequestHistory.add(getEntry(3, "10001"));
    ocspRequestHistory.add(getEntry(3, "10001"));
    ocspRequestHistory.add(getEntry(3, "99999"));

    assertGetOcspHistoryPart(1, "10001", 1);
    assertGetOcspHistoryPart(1, null, 1);
    assertGetOcspHistoryPart(1, "-1", 1);
    assertGetOcspHistoryPart(1, "0", 0);

    assertGetOcspHistoryPart(2, "10001", 2);
    assertGetOcspHistoryPart(2, null, 2);
    assertGetOcspHistoryPart(2, "-1", 2);
    assertGetOcspHistoryPart(2, "0", 0);

    assertGetOcspHistoryPart(3, "10001", 2);
    assertGetOcspHistoryPart(3, null, 3);
    assertGetOcspHistoryPart(3, "-1", 3);
    assertGetOcspHistoryPart(3, "0", 0);

    assertGetOcspHistoryPart(null, "10001", 5);
    assertGetOcspHistoryPart(-1, "10001", 5);
    assertGetOcspHistoryPart(0, "10001", 0);

    assertGetOcspHistoryPart(null, "99999", 1);
    assertGetOcspHistoryPart(-1, "99999", 1);
    assertGetOcspHistoryPart(0, "99999", 0);

    assertGetOcspHistoryPart(null, null, 6);
    assertGetOcspHistoryPart(-1, null, 6);
    assertGetOcspHistoryPart(null, "-1", 6);

    assertGetOcspHistoryPart(0, null, 0);
    assertGetOcspHistoryPart(0, "-1", 0);

    assertGetOcspHistoryPart(null, "0", 0);
    assertGetOcspHistoryPart(-1, "0", 0);
  }

  private void assertGetAndClearOcspHistoryPart(
      final Integer tslSeqNr, final String certSerialNrStr, final int expectedAmount) {

    OcspResponderManager.clearOcspHistory(ocspRespUri);

    ocspRequestHistory.add(getEntry(1, "10001"));

    ocspRequestHistory.add(getEntry(2, "10001"));
    ocspRequestHistory.add(getEntry(2, "10001"));

    ocspRequestHistory.add(getEntry(3, "10001"));
    ocspRequestHistory.add(getEntry(3, "10001"));
    ocspRequestHistory.add(getEntry(3, "99999"));

    BigInteger certSerialNr = null;

    if (certSerialNrStr != null) {
      certSerialNr = new BigInteger(certSerialNrStr);
    }

    List<OcspRequestHistoryEntryDto> entries;

    entries = OcspResponderManager.getAndClearOcspHistoryPart(ocspRespUri, tslSeqNr, certSerialNr);
    assertThat(entries).hasSize(expectedAmount);

    entries = OcspResponderManager.getOcspHistoryPart(ocspRespUri, tslSeqNr, certSerialNr);
    assertThat(entries).isEmpty();
  }

  @Test
  void testGetAndClearOcspHistoryPart() {

    assertGetAndClearOcspHistoryPart(1, "10001", 1);
    assertGetAndClearOcspHistoryPart(1, null, 1);
    assertGetAndClearOcspHistoryPart(1, "-1", 1);
    assertGetAndClearOcspHistoryPart(1, "0", 0);

    assertGetAndClearOcspHistoryPart(2, "10001", 2);
    assertGetAndClearOcspHistoryPart(2, null, 2);
    assertGetAndClearOcspHistoryPart(2, "-1", 2);
    assertGetAndClearOcspHistoryPart(2, "0", 0);

    assertGetAndClearOcspHistoryPart(3, "10001", 2);
    assertGetAndClearOcspHistoryPart(3, null, 3);
    assertGetAndClearOcspHistoryPart(3, "-1", 3);
    assertGetAndClearOcspHistoryPart(3, "0", 0);

    assertGetAndClearOcspHistoryPart(null, "10001", 5);
    assertGetAndClearOcspHistoryPart(-1, "10001", 5);
    assertGetAndClearOcspHistoryPart(0, "10001", 0);

    assertGetAndClearOcspHistoryPart(null, "99999", 1);
    assertGetAndClearOcspHistoryPart(-1, "99999", 1);
    assertGetAndClearOcspHistoryPart(0, "99999", 0);

    assertGetAndClearOcspHistoryPart(null, null, 6);
    assertGetAndClearOcspHistoryPart(-1, null, 6);
    assertGetAndClearOcspHistoryPart(null, "-1", 6);

    assertGetAndClearOcspHistoryPart(0, null, 0);
    assertGetAndClearOcspHistoryPart(0, "-1", 0);

    assertGetAndClearOcspHistoryPart(null, "0", 0);
    assertGetAndClearOcspHistoryPart(-1, "0", 0);
  }

  private void assertClearOcspHistory(
      final Integer tslSeqNr, final String certSerialNrStr, final int expectedAmount) {

    OcspResponderManager.clearOcspHistory(ocspRespUri);

    ocspRequestHistory.add(getEntry(1, "10001"));

    ocspRequestHistory.add(getEntry(2, "10001"));
    ocspRequestHistory.add(getEntry(2, "10001"));

    ocspRequestHistory.add(getEntry(3, "10001"));
    ocspRequestHistory.add(getEntry(3, "10001"));
    ocspRequestHistory.add(getEntry(3, "99999"));

    BigInteger certSerialNr = null;

    if (certSerialNrStr != null) {
      certSerialNr = new BigInteger(certSerialNrStr);
    }

    List<OcspRequestHistoryEntryDto> entries;

    entries = OcspResponderManager.getOcspHistoryPart(ocspRespUri, tslSeqNr, certSerialNr);
    assertThat(entries).hasSize(expectedAmount);

    OcspResponderManager.clearOcspHistory(ocspRespUri);

    entries = OcspResponderManager.getOcspHistoryPart(ocspRespUri, tslSeqNr, certSerialNr);
    assertThat(entries).isEmpty();

    entries =
        OcspResponderManager.getOcspHistoryPart(
            ocspRespUri,
            OcspResponderManager.IGNORE_SEQUENCE_NUMBER,
            OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);
    assertThat(entries).isEmpty();
  }

  @Test
  void testClearOcspHistory() {

    assertClearOcspHistory(1, "10001", 1);
    assertClearOcspHistory(1, null, 1);
    assertClearOcspHistory(1, "-1", 1);
    assertClearOcspHistory(1, "0", 0);

    assertClearOcspHistory(2, "10001", 2);
    assertClearOcspHistory(2, null, 2);
    assertClearOcspHistory(2, "-1", 2);
    assertClearOcspHistory(2, "0", 0);

    assertClearOcspHistory(3, "10001", 2);
    assertClearOcspHistory(3, null, 3);
    assertClearOcspHistory(3, "-1", 3);
    assertClearOcspHistory(3, "0", 0);

    assertClearOcspHistory(null, "10001", 5);
    assertClearOcspHistory(-1, "10001", 5);
    assertClearOcspHistory(0, "10001", 0);

    assertClearOcspHistory(null, "99999", 1);
    assertClearOcspHistory(-1, "99999", 1);
    assertClearOcspHistory(0, "99999", 0);

    assertClearOcspHistory(null, null, 6);
    assertClearOcspHistory(-1, null, 6);
    assertClearOcspHistory(null, "-1", 6);

    assertClearOcspHistory(0, null, 0);
    assertClearOcspHistory(0, "-1", 0);

    assertClearOcspHistory(null, "0", 0);
    assertClearOcspHistory(-1, "0", 0);
  }

  @Test
  void testClearAndNotConfigured() {

    OcspResponderManager.clear(ocspRespUri);

    final HttpResponse<byte[]> response =
        Unirest.post(ocspRespUri + OCSP_SSP_ENDPOINT + "/310000")
            .header(CONTENT_TYPE, MEDIA_TYPE_APPLICATION_OCSP_REQUEST)
            .header(ACCEPT, MEDIA_TYPE_APPLICATION_OCSP_RESPONSE)
            .body("")
            .asBytes();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_BAD_REQUEST);
  }
}
