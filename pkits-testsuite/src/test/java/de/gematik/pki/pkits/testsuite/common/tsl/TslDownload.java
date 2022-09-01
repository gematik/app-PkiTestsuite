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

package de.gematik.pki.pkits.testsuite.common.tsl;

import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint;
import static de.gematik.pki.pkits.testsuite.common.PkitsTestsuiteUtils.waitForEvent;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;

import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.ocsp.responder.OcspResponderException;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.testsuite.common.TestsuiteConstants;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.config.TestsuiteConfig;
import de.gematik.pki.pkits.testsuite.config.TestsuiteParameter.OcspSettings;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@Builder
public class TslDownload {

  private static final TestsuiteConfig testsuiteConfig = TestConfigManager.getTestsuiteConfig();

  private static final OcspSettings ocspSettings =
      testsuiteConfig.getTestsuiteParameter().getOcspSettings();

  private static final P12Container ocspSigner =
      P12Reader.getContentFromP12(
          ocspSettings.getKeystorePathOcsp().resolve(TestsuiteConstants.OCSP_SIGNER_FILENAME),
          ocspSettings.getSignerPassword());

  @Builder.Default private final int tslDownloadTimeoutSecs = 1;
  @Builder.Default private final int tslProcessingTimeSeconds = 3;
  private final byte @NonNull [] tslBytes;
  @NonNull private final String tslProvUri;
  @NonNull private final String ocspRespUri;
  @Builder.Default private final boolean ocspRequestExpected = true;
  @NonNull private final TslDownloadPoint tslDownloadPoint;
  @NonNull private X509Certificate tslSignerCert;

  public void waitUntilTslDownloadCompleted() {
    waitUntilTslDownloadCompleted(IGNORE_SEQUENCE_NUMBER);
  }

  public void waitUntilTslDownloadCompleted(final int sequenceNr) {
    configureOcspResponderTslSignerStatusGood();
    waitForTslDownload(sequenceNr);
    waitUntilOcspRequestForSigner();
  }

  private void configureOcspResponderTslSignerStatusGood() {
    try {
      TestEnvironment.configureOcspResponder(
          ocspRespUri,
          OcspResponderConfigDto.builder().eeCert(tslSignerCert).signer(ocspSigner).build());
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  private void waitForTslDownload(final int sequenceNr) {
    TestEnvironment.configureTslProvider(tslProvUri, tslBytes, tslDownloadPoint);
    waitForEvent(
        "TslDownloadHistoryHasEntry",
        tslDownloadTimeoutSecs,
        tslDownloadHistoryHasSpecificEntry(sequenceNr));
    final List<TslRequestHistoryEntryDto> l =
        TslProviderManager.getTslRequestHistoryPart(tslProvUri, sequenceNr);
    final int seqNrOfLastTslDownloadHistEntry = l.get(l.size() - 1).getSequenceNr();
    log.info("Expecting download from TSL with seqNr.: {}", sequenceNr);
    log.info("Last know TSL seqNr in history: {}", seqNrOfLastTslDownloadHistEntry);
    TslSequenceNr.getInstance().updateCurrentNrInTestobject(seqNrOfLastTslDownloadHistEntry);
  }

  private void waitUntilOcspRequestForSigner() {
    if (ocspRequestExpected) {
      final BigInteger tslSignerCertSerialNr = tslSignerCert.getSerialNumber();
      waitForEvent(
          "OcspRequestHistoryHasEntry for TSL signer cert " + tslSignerCertSerialNr,
          tslProcessingTimeSeconds,
          ocspRequestHistoryHasEntryForCert(tslSignerCertSerialNr));
    }
  }

  private Callable<Boolean> tslDownloadHistoryHasSpecificEntry(final int sequenceNr) {
    log.debug("Polling TSL download request history");
    return () -> !TslProviderManager.getTslRequestHistoryPart(tslProvUri, sequenceNr).isEmpty();
  }

  private Callable<Boolean> ocspRequestHistoryHasEntryForCert(final BigInteger certSerial) {
    log.debug("Polling TSL download request history");
    return () -> !OcspResponderManager.getOcspHistoryPart(ocspRespUri, certSerial).isEmpty();
  }
}
