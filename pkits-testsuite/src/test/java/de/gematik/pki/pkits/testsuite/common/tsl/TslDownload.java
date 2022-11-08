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
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;

import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.ocsp.responder.OcspResponderException;
import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.config.OcspSettings;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
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

  private static final TestSuiteConfig testSuiteConfig = TestConfigManager.getTestSuiteConfig();

  private static final OcspSettings ocspSettings =
      testSuiteConfig.getTestSuiteParameter().getOcspSettings();

  private static final P12Container ocspSigner =
      P12Reader.getContentFromP12(
          ocspSettings.getKeystorePathOcsp().resolve(TestSuiteConstants.OCSP_SIGNER_FILENAME),
          ocspSettings.getSignerPassword());

  @Builder.Default
  private final int tslDownloadTimeoutSecs =
      1; // TODO warum nicht das DL Intervall aus config direkt nehmen?

  @Builder.Default
  private final int tslProcessingTimeSeconds = 3; // TODO warum nicht aus config direkt nehmen?

  private final byte @NonNull [] tslBytes;
  @NonNull private final String tslProvUri;
  @NonNull private final String ocspRespUri;

  @Builder.Default
  private final boolean ocspRequestExpected = true; // TODO warum nicht aus config direkt nehmen?

  @NonNull private final TslDownloadPoint tslDownloadPoint;
  @NonNull private X509Certificate tslSignerCert; // TODO warum nicht aus config direkt nehmen?

  public void waitUntilTslDownloadCompleted() {
    waitUntilTslDownloadCompleted(IGNORE_SEQUENCE_NUMBER);
  }

  public void waitUntilTslDownloadCompleted(final int sequenceNr) {
    configureOcspResponderTslSignerStatusGood();
    waitForTslDownload(sequenceNr);
    waitUntilOcspRequestForSigner();
  }

  public void configureOcspResponderTslSignerStatusGood() {
    try {
      TestEnvironment.configureOcspResponder(
          ocspRespUri,
          OcspResponderConfigDto.builder().eeCert(tslSignerCert).signer(ocspSigner).build());
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  public void configureOcspResponderTslSignerStatusGood(
      final OcspResponderConfigDto.OcspResponderConfigDtoBuilder builder) {
    try {
      TestEnvironment.configureOcspResponder(ocspRespUri, builder.build());
    } catch (final OcspResponderException e) {
      throw new PkiCommonException("Could not configure OcspResponder", e);
    }
  }

  public void waitForTslDownload(final int sequenceNr) {

    TestEnvironment.configureTslProvider(tslProvUri, tslBytes, tslDownloadPoint);
    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry",
        tslDownloadTimeoutSecs,
        tslDownloadHistoryHasSpecificEntry(tslProvUri, sequenceNr));
    TestEnvironment.clearTslProviderConfig(tslProvUri);
  }

  public static Integer getSeqNrOfLastTslDownload(final String tslProvUri, final int sequenceNr) {
    log.info("Expecting download from TSL with seqNr.: {}", sequenceNr);

    final List<TslRequestHistoryEntryDto> historyEntryDtos =
        TslProviderManager.getTslRequestHistoryPart(tslProvUri, sequenceNr);

    // TODO use same variable names for sequenceNr, seqNr, etc.
    if (historyEntryDtos.isEmpty()) {
      log.info("history for seqNr {} is empty", sequenceNr);
      return null;
    }

    final int seqNrOfLastTslDownloadHistEntry =
        historyEntryDtos.get(historyEntryDtos.size() - 1).getSequenceNr();

    log.info("Last know TSL seqNr in history: {}", seqNrOfLastTslDownloadHistEntry);
    return seqNrOfLastTslDownloadHistEntry;
  }

  public void waitUntilOcspRequestForSigner() {
    if (ocspRequestExpected) {
      final BigInteger tslSignerCertSerialNr = tslSignerCert.getSerialNumber();
      PkitsTestSuiteUtils.waitForEvent(
          "OcspRequestHistoryHasEntry for TSL signer cert " + tslSignerCertSerialNr,
          tslProcessingTimeSeconds,
          ocspRequestHistoryHasEntryForCert(tslSignerCertSerialNr));
    }
    TestEnvironment.clearOcspResponderConfig(ocspRespUri);
  }

  public static Callable<Boolean> tslDownloadHistoryHasSpecificEntry(
      final String tslProvUri, final int sequenceNr) {
    log.debug("Polling TSL download request history, seqNr {}", sequenceNr);
    return () -> !TslProviderManager.getTslRequestHistoryPart(tslProvUri, sequenceNr).isEmpty();
  }

  private Callable<Boolean> ocspRequestHistoryHasEntryForCert(final BigInteger certSerial) {
    log.debug("Polling TSL download request history");
    return () -> !OcspResponderManager.getOcspHistoryPart(ocspRespUri, certSerial).isEmpty();
  }
}
