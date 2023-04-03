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
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.config.Afo;
import java.io.IOException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import javax.xml.datatype.DatatypeConfigurationException;
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
class TslVaApprovalTestsIT extends TslVaApprovalUtilsBaseIT {

  final Path tslSignerFromNotYetValidTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_notyetvalid_ta.p12");

  /** TSLTypeID 102 */
  static final Path tslTemplateTrustAnchorChange =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_TAchange.xml");

  /** TSLTypeID 174 */
  static final Path tslTemplateAlternativeTrustAnchorAlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA_altCA.xml");

  /** TSLTypeID 104 */
  static final Path tslTemplateAlternativeTrustAnchorTrustAnchorChange =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA_TAchange.xml");

  /** TSLTypeID 345 */
  private static final Path tslTemplateDefectTrustAnchorChangeExpired =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_expired.xml");

  /** TSLTypeID 178 */
  private static final Path tslTemplateInvalidAlternativeTrustAnchorExpiredAlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_invalid_altTA_expired_altCA.xml");

  /** TSLTypeID 347 */
  private static final Path tslTemplateDefectTrustAnchorChangeNotYetValid =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_notYetValid.xml");

  /** TSLTypeID 180 */
  private static final Path tslTemplateInvalidAlternativeTrustAnchorNotYetValidAlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_invalid_altTA_notYetValid_altCA.xml");

  /** TSLTypeID 355 */
  private static final Path tslTemplateDefectTrustAnchorChangeStartingTimeFuture =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_startingTimeFuture.xml");

  /** TSLTypeID 357 */
  private static final Path tslTemplateDefectTrustAnchorChangeTwoEntries =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_twoEntries.xml");

  /** TSLTypeID 361 */
  private static final Path tslTemplateDefectTrustAnchorChangeBroken =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_defect_TAchange_broken.xml");

  /** TSLTypeID 172 */
  private static final Path tslTemplateTrustAnchorChangeFuture =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_TAchange_future.xml");

  /** TSLTypeID 173 */
  static final Path tslTemplateTrustAnchorChangeAlternativeTrustAnchor2FutureShort =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_TAchange_altTA2_futureShort.xml");

  /** TSLTypeID 175 */
  static final Path tslTemplateAlternativeTrustAnchor2AlternativeCa =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA2_altCA.xml");

  /** TSLTypeID 177 */
  static final Path tslTemplateAlternativeTrustAnchor2TrustAnchorChange =
      Path.of(TSL_TEMPLATES_DIRNAME, "TSL_altTA2_TAchange.xml");

  private static final UseCaseResult SKIP_USECASE = null;

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

    updateTrustStore(
        tslTemplateTrustAnchorChange,
        defaultTslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    setExpectedOcspTslSeqNr(tslSequenceNr.getExpectedNrInTestObject());

    log.info("verifyUpdateTrustAnchor - new trust anchor should be activated now");

    verifyInvalidTrustAnchorWasNotImported(tslSettings.getAlternativeTemplate(), defaultTslSigner);

    log.info("verifyUpdateTrustAnchor step 2.3");
    printCurrentTslSeqNr();
    updateTrustStore(
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

    updateTrustStore(
        tslTemplateAlternativeTrustAnchorTrustAnchorChange,
        tslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfFirstValidCert(),
        USECASE_VALID);

    setExpectedOcspTslSeqNr(tslSequenceNr.getExpectedNrInTestObject());

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - finish\n\n");
  }

  private void tryToImportAnnouncedInvalidTrustAnchor(
      final Path tslTemplate,
      final Path tslSignerP12Path,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour)
      throws DatatypeConfigurationException, IOException {

    log.info("tryToImportAnnouncedInvalidTrustAnchor - start: tsl template {}", tslTemplate);

    updateTrustStore(
        tslTemplate,
        tslSignerP12Path,
        ocspRequestExpectationBehaviour,
        getPathOfAlternativeCertificate(),
        USECASE_INVALID);

    log.info("tryToImportAnnouncedInvalidTrustAnchor - finish\n\n");
  }

  private void verifyInvalidTrustAnchorWasNotImported(
      final Path tslTemplate, final Path tslSignerP12Path)
      throws DatatypeConfigurationException, IOException {

    log.info("verifyInvalidTrustAnchorWasNotImported - start: tslTemplate {}", tslTemplate);

    updateTrustStore(tslTemplate, tslSignerP12Path, OCSP_REQUEST_IGNORE, null, SKIP_USECASE);

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

    log.info("case 1: verify new trust anchor expired");
    initialStateWithAlternativeTemplate();

    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeExpired, defaultTslSigner, OCSP_REQUEST_EXPECT);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateInvalidAlternativeTrustAnchorExpiredAlternativeCa,
        tslSignerFromExpiredTrustAnchorP12Path);

    log.info("case 2: verify new trust anchor not yet valid");
    initialStateWithAlternativeTemplate();

    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeNotYetValid, defaultTslSigner, OCSP_REQUEST_EXPECT);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateInvalidAlternativeTrustAnchorNotYetValidAlternativeCa,
        tslSignerFromNotYetValidTrustAnchorP12Path);

    log.info("case 3: StatusStartingTime is expired");
    initialStateWithAlternativeTemplate();
    tryToImportAnnouncedInvalidTrustAnchor(
        tslTemplateDefectTrustAnchorChangeStartingTimeFuture,
        defaultTslSigner,
        OCSP_REQUEST_EXPECT);

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
        tslTemplateDefectTrustAnchorChangeTwoEntries, defaultTslSigner, OCSP_REQUEST_EXPECT);

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
        tslTemplateDefectTrustAnchorChangeBroken, defaultTslSigner, OCSP_REQUEST_EXPECT);

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
  void verifyHandlingOfStatusStartingTimeAndOverwriteAnnouncedInactiveTrustAnchors(
      final int testOrder, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    if (testOrder == 1) {
      log.info("execute test case verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor");
      verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor(testInfo);
    } else {
      log.info("execute test case  verifyOverwriteAnnouncedTrustAnchor");
      verifyOverwriteAnnouncedInactiveTrustAnchor(testInfo);
    }
  }

  private void waitWithExtraSeconds(long waitingTimeSeconds) {
    final long extraSeconds = 5;
    waitingTimeSeconds += extraSeconds;
    log.info("wait for activation of new trust anchor for {} seconds", waitingTimeSeconds);
    PkitsCommonUtils.waitSeconds(waitingTimeSeconds);
    log.info("waiting is over");
  }

  private void verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = GemLibPkiUtils.now().plusSeconds(tripleTslDownloadTime);

    log.info("StartingStatusTime of new trust anchor: {}", newActivationTime);

    importNewValidTrustAnchor(
        tslTemplateTrustAnchorChange,
        defaultTslSigner,
        newActivationTime,
        OcspSeqNrUpdateMode.UPDATE_OCSP_SEQ_NR);

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

      setExpectedOcspTslSeqNr(IGNORE_SEQUENCE_NUMBER);
      fallBackFromAlternativeToDefaultTrustAnchorAndCheck(alternativeTslSignerP12Path);
      Assertions.fail(
          "a trust anchor was unexpectedly imported into the test object - a fallback was performed"
              + " to switch to the default trust anchor");
    }

    waitWithExtraSeconds(tripleTslDownloadTime);
    log.info(
        "new trust anchor should be activated now - StartingStatusTime: {}", newActivationTime);

    verifyInvalidTrustAnchorWasNotImported(tslSettings.getAlternativeTemplate(), defaultTslSigner);

    importNewValidTrustAnchor(
        tslTemplateAlternativeTrustAnchorAlternativeCa,
        alternativeTslSignerP12Path,
        null,
        OcspSeqNrUpdateMode.DO_NOT_UPDATE_OCSP_SEQ_NR);

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

  private void verifyOverwriteAnnouncedInactiveTrustAnchor(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final ZonedDateTime now = GemLibPkiUtils.now();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = now.plusSeconds(tripleTslDownloadTime);

    importNewValidTrustAnchor(
        tslTemplateTrustAnchorChangeFuture,
        defaultTslSigner,
        newActivationTime,
        OcspSeqNrUpdateMode.DO_NOT_UPDATE_OCSP_SEQ_NR);

    final long tripleTslDownloadTimeM10 = tripleTslDownloadTime - 10;
    if (tripleTslDownloadTimeM10 < 0) {
      // TODO implement fallback
      log.error("activation of new trust anchor is in the past (too early)");
    }

    final ZonedDateTime newActivationTime2 = now.plusSeconds(tripleTslDownloadTimeM10);

    log.info("StartingStatusTime of new trust anchor: {}", newActivationTime2);

    importNewValidTrustAnchor(
        tslTemplateTrustAnchorChangeAlternativeTrustAnchor2FutureShort,
        defaultTslSigner,
        newActivationTime2,
        OcspSeqNrUpdateMode.UPDATE_OCSP_SEQ_NR);

    waitWithExtraSeconds(tripleTslDownloadTime);

    log.info(
        "new trust anchor should be activated now - StartingStatusTime: {}", newActivationTime2);

    verifyInvalidTrustAnchorWasNotImported(
        tslTemplateAlternativeTrustAnchorAlternativeCa, alternativeTslSignerP12Path);

    importNewValidTrustAnchor(
        tslTemplateAlternativeTrustAnchor2AlternativeCa,
        alternativeSecondTslSignerP12Path,
        null,
        OcspSeqNrUpdateMode.DO_NOT_UPDATE_OCSP_SEQ_NR);

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_VALID,
        OCSP_RESP_TYPE_DEFAULT_USECASE,
        OCSP_REQUEST_EXPECT);

    importNewValidTrustAnchor(
        tslTemplateAlternativeTrustAnchor2TrustAnchorChange,
        alternativeSecondTslSignerP12Path,
        null,
        OcspSeqNrUpdateMode.UPDATE_OCSP_SEQ_NR);

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
      setExpectedOcspTslSeqNr(IGNORE_SEQUENCE_NUMBER);
      fallBackFromAlternativeToDefaultTrustAnchorAndCheck(alternativeTslSignerP12Path);
      Assertions.fail(
          "a trust anchor was unexpectedly imported into the test object - a fallback was performed"
              + " to switch to the default trust anchor");
    }
  }
}
