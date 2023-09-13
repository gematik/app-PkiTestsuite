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

package de.gematik.pki.pkits.tsl.provider.api;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.util.List;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
@Slf4j
class TslProviderManagerTest {

  @LocalServerPort private int localServerPort;

  @Autowired TslRequestHistory tslRequestHistory;

  private String tslProviderUri;

  @BeforeEach
  void setup() {
    tslProviderUri = "http://localhost:" + localServerPort;
  }

  @Test
  void testCheckHealthOk() {
    PkitsCommonUtils.checkHealth(log, "TslProvider", tslProviderUri);
  }

  public static TslRequestHistoryEntryDto getEntry(
      final int tslSeqNr, final String tslDownloadEndpoint) {
    return new TslRequestHistoryEntryDto(tslSeqNr, tslDownloadEndpoint, true, "HTTP/1.1");
  }

  private void assertGetOcspHistoryPart(
      final Integer tslSeqNr,
      final TslDownloadEndpointType tslDownloadEndpointType,
      final int expectedAmount) {

    final List<TslRequestHistoryEntryDto> entries =
        TslProviderManager.getTslRequestHistoryPart(
            tslProviderUri, tslSeqNr, tslDownloadEndpointType);

    assertThat(entries).hasSize(expectedAmount);
  }

  @Test
  void testGetOcspHistoryPart() {

    TslProviderManager.clearTslHistory(tslProviderUri);

    tslRequestHistory.add(getEntry(1, TSL_XML_PRIMARY_ENDPOINT));

    tslRequestHistory.add(getEntry(2, TSL_HASH_PRIMARY_ENDPOINT));
    tslRequestHistory.add(getEntry(2, TSL_HASH_PRIMARY_ENDPOINT));

    tslRequestHistory.add(getEntry(3, TSL_XML_BACKUP_ENDPOINT));
    tslRequestHistory.add(getEntry(3, TSL_XML_BACKUP_ENDPOINT));
    tslRequestHistory.add(getEntry(3, TSL_XML_BACKUP_ENDPOINT));

    tslRequestHistory.add(getEntry(4, TSL_HASH_BACKUP_ENDPOINT));
    tslRequestHistory.add(getEntry(4, TSL_HASH_BACKUP_ENDPOINT));
    tslRequestHistory.add(getEntry(4, TSL_HASH_BACKUP_ENDPOINT));
    tslRequestHistory.add(getEntry(4, TSL_HASH_BACKUP_ENDPOINT));

    tslRequestHistory.add(getEntry(1000, TSL_XML_PRIMARY_ENDPOINT));
    tslRequestHistory.add(getEntry(1000, TSL_HASH_PRIMARY_ENDPOINT));
    tslRequestHistory.add(getEntry(1000, TSL_XML_BACKUP_ENDPOINT));
    tslRequestHistory.add(getEntry(1000, TSL_HASH_BACKUP_ENDPOINT));

    assertGetOcspHistoryPart(IGNORE_SEQUENCE_NUMBER, TslDownloadEndpointType.ANY_ENDPOINT, 14);
    assertGetOcspHistoryPart(IGNORE_SEQUENCE_NUMBER, TslDownloadEndpointType.XML_ENDPOINTS, 6);
    assertGetOcspHistoryPart(IGNORE_SEQUENCE_NUMBER, TslDownloadEndpointType.HASH_ENDPOINTS, 8);

    assertGetOcspHistoryPart(1, TslDownloadEndpointType.XML_ENDPOINTS, 1);
    assertGetOcspHistoryPart(1, TslDownloadEndpointType.HASH_ENDPOINTS, 0);

    assertGetOcspHistoryPart(2, TslDownloadEndpointType.XML_ENDPOINTS, 0);
    assertGetOcspHistoryPart(2, TslDownloadEndpointType.HASH_ENDPOINTS, 2);

    assertGetOcspHistoryPart(3, TslDownloadEndpointType.XML_ENDPOINTS, 3);
    assertGetOcspHistoryPart(3, TslDownloadEndpointType.HASH_ENDPOINTS, 0);

    assertGetOcspHistoryPart(4, TslDownloadEndpointType.XML_ENDPOINTS, 0);
    assertGetOcspHistoryPart(4, TslDownloadEndpointType.HASH_ENDPOINTS, 4);

    assertGetOcspHistoryPart(1000, TslDownloadEndpointType.ANY_ENDPOINT, 4);
    assertGetOcspHistoryPart(1000, TslDownloadEndpointType.HASH_ENDPOINTS, 2);
    assertGetOcspHistoryPart(1000, TslDownloadEndpointType.HASH_ENDPOINTS, 2);

    TslProviderManager.clearTslHistory(tslProviderUri);
    assertGetOcspHistoryPart(IGNORE_SEQUENCE_NUMBER, TslDownloadEndpointType.ANY_ENDPOINT, 0);
  }

  @Test
  void testClearAndNotConfigured() {

    TslProviderManager.clear(tslProviderUri);

    final HttpResponse<byte[]> response =
        Unirest.get(
                "%s%s?%s=31000"
                    .formatted(tslProviderUri, TSL_XML_PRIMARY_ENDPOINT, TSL_SEQNR_PARAM_ENDPOINT))
            .asBytes();

    assertThat(response.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
    assertThat(new String(response.getBody())).isEqualTo(PkitsConstants.NOT_CONFIGURED);
  }
}
