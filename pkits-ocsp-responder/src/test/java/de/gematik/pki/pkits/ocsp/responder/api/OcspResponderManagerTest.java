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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistory;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import java.math.BigInteger;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
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

  private OcspRequestHistoryEntryDto getEntry(final String certCerialNr) {
    return new OcspRequestHistoryEntryDto(
        new BigInteger(certCerialNr), ZonedDateTime.now().toString(), 3);
  }

  @Test
  void t01_checkHealthOk() {
    PkitsCommonUtils.checkHealth(log, "OcspResponder", ocspRespUri);
  }

  @Test
  void t02_checkHealthException() {
    final String badOcspRespUri = "http://localhostX:" + localServerPort;
    Assertions.assertThatThrownBy(
            () -> PkitsCommonUtils.checkHealth(log, "OcspResponder", badOcspRespUri))
        .isInstanceOf(PkiCommonException.class)
        .hasMessageContaining("OcspResponder has health problem");
  }

  @Test
  void t03_getOcspHistoryPart() {
    final String ocspRespUri = "http://localhost:" + localServerPort;
    OcspResponderManager.clearOcspHistory(ocspRespUri);

    ocspRequestHistory.add(getEntry("10001"));

    final List<OcspRequestHistoryEntryDto> entries =
        OcspResponderManager.getOcspHistoryPart(ocspRespUri, new BigInteger("10001"));

    assertThat(entries).hasSize(1);
  }

  @Test
  void t04_getAndClearOcspHistoryPart() {
    final String ocspRespUri = "http://localhost:" + localServerPort;
    OcspResponderManager.clearOcspHistory(ocspRespUri);

    ocspRequestHistory.add(getEntry("20002"));

    List<OcspRequestHistoryEntryDto> entries;

    entries = OcspResponderManager.getAndClearOcspHistoryPart(ocspRespUri, new BigInteger("20002"));
    assertThat(entries).hasSize(1);

    entries = OcspResponderManager.getOcspHistoryPart(ocspRespUri, new BigInteger("20002"));
    assertThat(entries).isEmpty();
  }

  @Test
  void t05_clearOcspHistory() {
    final String ocspRespUri = "http://localhost:" + localServerPort;
    OcspResponderManager.clearOcspHistory(ocspRespUri);

    ocspRequestHistory.add(getEntry("20002"));

    List<OcspRequestHistoryEntryDto> entries =
        OcspResponderManager.getOcspHistoryPart(ocspRespUri, new BigInteger("20002"));

    assertThat(entries.size()).isNotZero();

    OcspResponderManager.clearOcspHistory(ocspRespUri);

    entries = OcspResponderManager.getOcspHistoryPart(ocspRespUri, new BigInteger("20002"));
    assertThat(entries).isEmpty();
  }
}
