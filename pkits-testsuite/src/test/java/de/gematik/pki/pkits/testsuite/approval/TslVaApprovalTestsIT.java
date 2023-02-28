/*
 * Copyright (c) 2023 gematik GmbH
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

import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_DEFAULT_USECASE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_VALID;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.config.Afo;
import java.io.IOException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI TSL Trust Anchor approval tests.")
@Order(9)
class TslVaApprovalTestsIT extends ApprovalTestsBaseIT {

  final Path alternativeTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-9-TEST-ONLY.p12");

  final Path alternativeSecondTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-16-TEST-ONLY.p12");

  final Path tslSignerFromExpiredTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_expired_ta.p12");

  final Path tslSignerFromNotYetValidTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_notyetvalid_ta.p12");

  private static final Path tslTemplateTrustAnchorChange =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_TAchange.xml");

  private static final Path tslTemplateAlternativeTrustAnchorAlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA_altCA.xml");

  private static final Path tslTemplateAlternativeTrustAnchorTrustAnchorChange =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA_TAchange.xml");

  private static final Path tslTemplateDefectTrustAnchorChangeExpired =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_expired.xml");

  private static final Path tslTemplateInvalidAlternativeTrustAnchorExpiredAlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_invalid_altTA_expired_altCA.xml");

  private static final Path tslTemplateDefectTrustAnchorChangeNotYetValid =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_notYetValid.xml");

  private static final Path tslTemplateInvalidAlternativeTrustAnchorNotYetValidAlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_invalid_altTA_notYetValid_altCA.xml");

  private static final Path tslTemplateDefectTrustAnchorChangeStartingTimeFuture =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_startingTimeFuture.xml");

  private static final Path tslTemplateDefectTrustAnchorChangeTwoEntries =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_twoEntries.xml");

  private static final Path tslTemplateDefectTrustAnchorChangeBroken =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_broken.xml");

  private static final Path tslTemplateTrustAnchorChangeFuture =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_TAchange_future.xml");

  private static final Path tslTemplateTrustAnchorChangeAlternativeTrsutAnchor2FutureShort =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_TAchange_altTA2_futureShort.xml");

  private static final Path tslTemplateAlternativeTrustAnchor2AlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA2_altCA.xml");

  private static final Path tslTemplateAlternativeTrustAnchor2TrustAnchorChange =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA2_TAchange.xml");

  private static final UseCaseResult SKIP_USECASE = null;

  void initialStateWithAlternativeTemplate() throws DatatypeConfigurationException, IOException {

    log.info("initialStateWithAlternativeTemplate - start");
    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

    final Path tslTemplate = tslSettings.getAlternativeTemplate();

    final TslDownload tslDownload =
        getTslDownloadWithTemplateAndSigner(
            offeredSeqNr,
            tslTemplate,
            tslSigner,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(IGNORE_SEQUENCE_NUMBER);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    final Path certPath = getPathOfAlternativeCertificate();
    useCaseWithCert(certPath, USECASE_VALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_EXPECT);
    log.info("initialStateWithAlternativeTemplate - finish\n\n");
  }

  /** gematikId: UE_PKI_TC_0106_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(afoId = "GS-A_4643", description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL")
  @DisplayName("Test updating trust anchor")
  void verifyUpdateTrustAnchor(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    log.info("verifyUpdateTrustAnchor step 2.1");

    // XX 2 tslDownload
    bringInTslDownload(
        tslTemplateTrustAnchorChange,
        tslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    verifyInvalidTrustAnchorWasNotImported(tslSettings.getAlternativeTemplate(), tslSigner);

    log.info("verifyUpdateTrustAnchor step 2.3");

    // XX 3 tslDownload
    bringInTslDownload(
        tslTemplateAlternativeTrustAnchorAlternativeCa,
        alternativeTslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);

    fallBackFromAlternativeToDefaultTrustAnchorAndCheck(alternativeTslSignerP12Path);
  }

  private void fallBackFromAlternativeToDefaultTrustAnchorAndCheck(final Path tslSignerP12Path)
      throws DatatypeConfigurationException, IOException {

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - start");

    // XX 4 tslDownload
    bringInTslDownload(
        tslTemplateAlternativeTrustAnchorTrustAnchorChange,
        tslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfFirstValidCert(),
        USECASE_VALID);

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - finish\n\n");
  }

  private void tryToImportAnnouncedInvalidTrustAnchor(
      final Path tslTemplate,
      final Path tslSignerP12Path,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour)
      throws DatatypeConfigurationException, IOException {

    log.info("tryToImportAnnouncedInvalidTrustAnchor - start: tsl template {}", tslTemplate);

    // XX 5 tslDownload
    bringInTslDownload(
        tslTemplate,
        tslSignerP12Path,
        ocspRequestExpectationBehaviour,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    log.info("tryToImportAnnouncedInvalidTrustAnchor - finish\n\n");
  }

  void setNewActivationTime(
      final TslDownload tslDownload,
      @NonNull final Path tslSignerPath,
      final ZonedDateTime newActivationTime)
      throws DatatypeConfigurationException, IOException {

    byte[] tslBytes = tslDownload.getTslBytes();
    tslBytes =
        TslModifier.modifiedStatusStartingTime(
            tslBytes,
            PkitsConstants.GEMATIK_TEST_TSP,
            TslConstants.STI_SRV_CERT_CHANGE,
            null,
            newActivationTime);

    signAndSetTslBytes(tslDownload, tslSignerPath, tslBytes);
    writeTsl(tslDownload, "_modified");
  }

  private void importNewValidTrustAnchor(
      @NonNull final Path tslTemplate,
      @NonNull final Path tslSignerPath,
      final ZonedDateTime newActivationTime)
      throws DatatypeConfigurationException, IOException {

    log.info("importNewValidTrustAnchor - start: tsl template {}", tslTemplate);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

    // XX 6 tslDownload
    final TslDownload tslDownload =
        getTslDownloadWithTemplateAndSigner(
            offeredSeqNr,
            tslTemplate,
            tslSignerPath,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    if (newActivationTime != null) {
      setNewActivationTime(tslDownload, tslSignerPath, newActivationTime);
    }

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(offeredSeqNr);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    log.info("importNewValidTrustAnchor - finish\n\n");
  }

  void verifyInvalidTrustAnchorWasNotImported(final Path tslTemplate, final Path tslSignerP12Path)
      throws DatatypeConfigurationException, IOException {

    log.info("verifyInvalidTrustAnchorWasNotImported - start: tslTemplate {}", tslTemplate);

    // XX 7 tslDownload
    bringInTslDownload(tslTemplate, tslSignerP12Path, OCSP_REQUEST_IGNORE, null, SKIP_USECASE);

    final Path certPath = getPathOfAlternativeCertificate();

    try {
      useCaseWithCert(
          certPath, USECASE_INVALID, OCSP_RESP_TYPE_DEFAULT_USECASE, OCSP_REQUEST_DO_NOT_EXPECT);
      log.info("verifyInvalidTrustAnchorWasNotImported - finish.\n\n");

      // TODO make exception more specific, also have a look at useCaseWithCert
      // TODO think about and implement fallBackToDefaultTrustAnchorAndCheck for the above
      // useCaseWithCert; also in other new trust anchor import test cases
    } catch (final Exception e) {

      // fallBackToDefaultTrustAnchorAndCheck(tslTemplateAlternativeTrustAnchorTrustAnchorChange,
      // tslSignerP12Path);
      log.error(
          """



              defect trust anchor imported in the test object - a fallback is not implemented yet -> all further tests are inconclusive


              """);

      // TODO stop test suite -> no further test should be executed
      throw e;
    }
  }

  /** gematikId: UE_PKI_TC_0106_002 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(
      afoId = "GS-A_4643",
      description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL - Schritt 4")
  @DisplayName("Test updating trust anchor with certificates that have invalid times")
  void verifyNewTrustAnchorInvalidTime(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    log.info("verify new trust anchor expired");
    initialStateWithAlternativeTemplate();
    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeExpired, tslSigner, OCSP_REQUEST_EXPECT);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateInvalidAlternativeTrustAnchorExpiredAlternativeCa,
        tslSignerFromExpiredTrustAnchorP12Path);

    log.info("verify new trust anchor not yet valid");
    initialStateWithAlternativeTemplate();
    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeNotYetValid, tslSigner, OCSP_REQUEST_EXPECT);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateInvalidAlternativeTrustAnchorNotYetValidAlternativeCa,
        tslSignerFromNotYetValidTrustAnchorP12Path);

    // TODO after PKITS-354 implemented, check logs that the trust anchor is not saved, as
    // StartingStatusTime > notAfter

    initialStateWithAlternativeTemplate();
    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeStartingTimeFuture, tslSigner, OCSP_REQUEST_EXPECT);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0106_004 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(
      afoId = "GS-A_4643",
      description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL - Schritt 1")
  @DisplayName("Test multiple announced trust anchors in single TSL")
  void verifyMultipleAnnouncedTrustAnchorsInTsl(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    initialStateWithAlternativeTemplate();

    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeTwoEntries, tslSigner, OCSP_REQUEST_EXPECT);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateAlternativeTrustAnchorAlternativeCa, alternativeTslSignerP12Path);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateAlternativeTrustAnchorAlternativeCa, alternativeSecondTslSignerP12Path);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0106_007 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(
      afoId = "GS-A_4643",
      description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL - Schritt 2")
  @DisplayName("Test for an announced broken trust anchor and cannot be extracted")
  void verifyNewTrustAnchorsIsBroken(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);

    initialStateWithAlternativeTemplate();

    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeBroken, tslSigner, OCSP_REQUEST_EXPECT);

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);
  }

  /** gematikId: UE_PKI_TC_0106_005, UE_PKI_TC_0106_006 */
  @ParameterizedTest
  @ValueSource(ints = {1, 2})
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(
      afoId = "GS-A_4643",
      description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL - Schritt 6")
  @DisplayName(
      "Test overwrite behaviour and proper handling of StatusStartingTime of announced trust"
          + " anchors")
  void verifyHandlingOfStatusStartingTimeAndOverwriteOfAnnouncedTrustAnchors(
      final int testOrder, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    if (testOrder == 1) {
      log.info("execute test case verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor");
      verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor(testInfo);
    } else {
      log.info("execute test case  verifyOverwriteAnnouncedTrustAnchor");
      verifyOverwriteAnnouncedTrustAnchor(testInfo);
    }
  }

  private void waitWithExtraSeconds(long waitingTimeSeconds) {
    final long extraSeconds = 5;
    waitingTimeSeconds += extraSeconds;
    log.info("wait for activation of new trust anchor for {} seconds", waitingTimeSeconds);
    PkitsCommonUtils.waitSeconds(waitingTimeSeconds);
    log.info("waiting is over");
  }

  void verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = GemLibPkiUtils.now().plusSeconds(tripleTslDownloadTime);

    log.info("StartingStatusTime of new trust anchor: {}", newActivationTime);

    importNewValidTrustAnchor(tslTemplateTrustAnchorChange, tslSigner, newActivationTime);

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_INVALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_DO_NOT_EXPECT);

    try {
      tryToImportAnnouncedInvalidTrustAnchor(
          tslTemplateAlternativeTrustAnchorAlternativeCa,
          alternativeTslSignerP12Path,
          OCSP_REQUEST_IGNORE);
    } catch (final Exception e) {
      // TODO integrate this fallback into tryToImportAnnouncedInvalidTrustAnchor around
      //      useCaseWithCert

      fallBackFromAlternativeToDefaultTrustAnchorAndCheck(alternativeTslSignerP12Path);
      Assertions.fail(
          "a trust anchor was unexpectedly imported into the test object - a fallback was performed"
              + " to switch to the default trust anchor");
    }

    waitWithExtraSeconds(tripleTslDownloadTime);

    verifyInvalidTrustAnchorWasNotImported(tslSettings.getAlternativeTemplate(), tslSigner);

    importNewValidTrustAnchor(
        tslTemplateAlternativeTrustAnchorAlternativeCa, alternativeTslSignerP12Path, null);

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);

    fallBackFromAlternativeToDefaultTrustAnchorAndCheck(alternativeTslSignerP12Path);
  }

  private static long getTripleTslDownloadTime() {
    long tripleTslDownloadTime =
        3L
            * (testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds()
                + testSuiteConfig.getTestObject().getTslProcessingTimeSeconds());

    // In case the OCSP Wait time (OCSP Grace Period + delta) is bigger than TSL-DL-interval, add 2
    // OCSP Wait time (one for each TSL DL expected to occur before the new trust anchor is
    // activated)

    final int ocspWaitTime =
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds()
            + ocspSettings.getGracePeriodExtraDelay();

    if (testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds() < ocspWaitTime) {
      tripleTslDownloadTime += 2L * ocspWaitTime;
    }
    return tripleTslDownloadTime;
  }

  void verifyOverwriteAnnouncedTrustAnchor(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final ZonedDateTime now = GemLibPkiUtils.now();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = now.plusSeconds(tripleTslDownloadTime);

    importNewValidTrustAnchor(tslTemplateTrustAnchorChangeFuture, tslSigner, newActivationTime);

    final long tripleTslDownloadTimeM10 = tripleTslDownloadTime - 10;
    if (tripleTslDownloadTimeM10 < 0) {
      // TODO implement fallback
      log.error("activation of new trust anchor is in the past (too early)");
    }

    final ZonedDateTime newActivationTime2 = now.plusSeconds(tripleTslDownloadTimeM10);

    log.info("StartingStatusTime of new trust anchor: {}", newActivationTime2);

    importNewValidTrustAnchor(
        tslTemplateTrustAnchorChangeAlternativeTrsutAnchor2FutureShort,
        tslSigner,
        newActivationTime2);

    waitWithExtraSeconds(tripleTslDownloadTime);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateAlternativeTrustAnchorAlternativeCa, alternativeTslSignerP12Path);

    importNewValidTrustAnchor(
        tslTemplateAlternativeTrustAnchor2AlternativeCa, alternativeSecondTslSignerP12Path, null);

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);

    importNewValidTrustAnchor(
        tslTemplateAlternativeTrustAnchor2TrustAnchorChange,
        alternativeSecondTslSignerP12Path,
        null);

    try {

      useCaseWithCert(
          getPathOfFirstValidCert(),
          USECASE_VALID,
          OCSP_RESP_TYPE_DEFAULT_USECASE,
          OCSP_REQUEST_EXPECT);

    } catch (final Exception e) {
      log.error(
          "failed to execute use case: very likely because of wrong trust anchor in test object",
          e);
      fallBackFromAlternativeToDefaultTrustAnchorAndCheck(alternativeTslSignerP12Path);
      Assertions.fail(
          "a trust anchor was unexpectedly imported into the test object - a fallback was performed"
              + " to switch to the default trust anchor");
    }
  }
}
