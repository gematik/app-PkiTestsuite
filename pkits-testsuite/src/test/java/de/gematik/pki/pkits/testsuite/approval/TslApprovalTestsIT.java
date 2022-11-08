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

package de.gematik.pki.pkits.testsuite.approval;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.io.IOException;
import java.util.List;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;

@Slf4j
@DisplayName("PKI TSL approval tests.")
@TestMethodOrder(OrderAnnotation.class)
class TslApprovalTestsIT extends ApprovalTestsBaseIT {

  @Test
  @Afo(
      afoId = "TIP1-A_5120",
      description = "Clients des TSL-Dienstes: HTTP-Komprimierung unterstützen")
  @DisplayName("Test compression of TSL download")
  void verifyTslDownloadCompression(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadDefaultTemplate(offeredSeqNr);

    tslDownload.configureOcspResponderTslSignerStatusGood();
    TestEnvironment.configureTslProvider(
        tslProvUri, tslDownload.getTslBytes(), tslDownload.getTslDownloadPoint());

    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry",
        tslDownload.getTslDownloadTimeoutSecs(),
        TslDownload.tslDownloadHistoryHasSpecificEntry(
            tslDownload.getTslProvUri(), tslSequenceNr.getExpectedNrInTestObject()));
    tslDownload.waitUntilOcspRequestForSigner();

    final List<TslRequestHistoryEntryDto> historyEntryDtos =
        TslProviderManager.getTslRequestHistoryPart(
            tslProvUri, tslSequenceNr.getExpectedNrInTestObject());

    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);
    tslSequenceNr.saveCurrentTestObjectSeqNr(offeredSeqNr);

    assertThat(historyEntryDtos).isNotEmpty();

    final TslRequestHistoryEntryDto historyEntryDto =
        historyEntryDtos.get(historyEntryDtos.size() - 1);

    assertThat(historyEntryDto.isGzipCompressed())
        .as("TSL download requests has to contain accept-encoding: gzip")
        .isTrue();
    assertThat(historyEntryDto.getProtocol())
        .as("TSL download requests has to be with http version 1.1")
        .isEqualTo("HTTP/1.1");
  }
}
