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

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.time.ZonedDateTime;
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
class TslTaApprovalTests extends ApprovalTestsBase {

  private static final String STARTINGSTATUSTIME_ANNOUNCED_TA_MESSAGE =
      "StartingStatusTime of announced trust anchor: {}";

  /** gematikId: UE_PKI_TC_0106_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(afoId = "GS-A_4643", description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL")
  @DisplayName("Test updating trust anchor")
  void verifyUpdateTrustAnchor(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    updateTrustStore(
        "Offer a TSL with announcement of trust anchor change.",
        newTslGenerator("announceAlternativeFirstTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    log.info("verifyUpdateTrustAnchor - new trust anchor should be activated now");

    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs, signed with old (no longer active) trust anchor.",
        "invalidDefaultTrustAnchorWithAlternativeCAs",
        CreateTslTemplate.alternativeTsl(),
        defaultTslSigner);

    updateTrustStore(
        "Offer a TSL (with alternate test CAs), signed with the new (announced) first alternative"
            + " trust anchor.",
        newTslGenerator("alternativeFirstTrustAnchorWithAlternativeCAs")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                TslGenerator.alternativeTslSignerP12Path),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID));

    fallBackFromAlternativeToDefaultTrustAnchorAndCheck(TslGenerator.alternativeTslSignerP12Path);
  }

  private void fallBackFromAlternativeToDefaultTrustAnchorAndCheck(final Path tslSignerP12Path) {

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - start");

    updateTrustStore(
        getSwitchMessage(TA_NAME_ALT1, TA_NAME_DEFAULT),
        newTslGenerator("fallbackFromAlternativeFirstTrustAnchorToDefault")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(), tslSignerP12Path),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - finish\n\n");
  }

  private void offerTslWithNewTaAndVerifyItWasNotImported(
      final String description,
      final String tslName,
      final TrustStatusListType tsl,
      final Path tslSignerP12Path) {

    log.info("Test if Trust Anchor was erroneously imported");
    log.info("offerTslWithNewTaAndVerifyItWasNotImported - start: tslName {}", tslName);

    updateTrustStore(
        description,
        newTslGenerator(tslName).getStandardTslDownload(tsl, tslSignerP12Path),
        OCSP_REQUEST_IGNORE,
        WITHOUT_USECASE);

    try {
      useCaseWithCert(
          getPathOfAlternativeCertificate(),
          USECASE_INVALID,
          OCSP_RESP_WITH_PROVIDED_CERT,
          OCSP_REQUEST_DO_NOT_EXPECT);

      log.info("offerTslWithNewTaAndVerifyItWasNotImported - finish.\n\n");

      // TODO make exception more specific, also have a look at useCaseWithCert
      // TODO think about and implement fallBackToDefaultTrustAnchorAndCheck for the above
      // useCaseWithCert; also in other new trust anchor import test cases
    } catch (final Exception e) {

      // fallBackToDefaultTrustAnchorAndCheck(CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(),
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
  void verifyNewTrustAnchorInvalidTime(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    // ---------------------------------------------------------------------------------

    log.info("start case 1: verify new trust anchor expired");
    initialStateWithAlternativeTemplate();

    updateTrustStore(
        "Try to import invalid trust anchor: offer a TSL announcing a new trust anchor (but"
            + " expired).",
        newTslGenerator("case1AnnounceExpiredTrustAnchor")
            .getStandardTslDownload(CreateTslTemplate.defectTrustAnchorChangeExpiredTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and the TSL signer certificate from the new trust anchor"
            + " (but expired).",
        "case1ExpiredTrustAnchorWithAlternativeCAs",
        CreateTslTemplate.invalidAlternativeTrustAnchorExpiredAlternativeCaTsl(),
        TslGenerator.tslSignerFromExpiredTrustAnchorP12Path);

    // ---------------------------------------------------------------------------------

    log.info("start case 2: verify new trust anchor not yet valid");
    initialStateWithAlternativeTemplate();
    updateTrustStore(
        "Try to import invalid trust anchor: offer a TSL announcing a new trust anchor (but not yet"
            + " valid).",
        newTslGenerator("case2AnnounceNotYetValidTrustAnchor")
            .getStandardTslDownload(CreateTslTemplate.defectTrustAnchorChangeNotYetValidTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and with the TSL signer certificate from the new trust"
            + " anchor (but not yet valid).",
        "case2NotYetValidTrustAnchorWithAlternativeCAs",
        CreateTslTemplate.invalidAlternativeTrustAnchorNotYetValidAlternativeCaTsl(),
        TslGenerator.tslSignerFromNotYetValidTrustAnchorP12Path);

    // ---------------------------------------------------------------------------------
    log.info("case 3: StatusStartingTime is expired");
    initialStateWithAlternativeTemplate();
    updateTrustStore(
        "Try to import invalid trust anchor: offer a TSL announcing a new valid trust anchor, that"
            + " would expire to the time of specified StatusStartingTime.",
        newTslGenerator("case3AnnounceValidTrustAnchorExpiringAtStatusStartingTimeInFuture")
            .getStandardTslDownload(
                CreateTslTemplate.defectTrustAnchorChangeStartingTimeFutureTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    // ---------------------------------------------------------------------------------
    log.info(
        "Check if expected TSL is in the test object (TSL sequence number is in"
            + " ServiceSupplyPoint)");
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
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
  void verifyMultipleAnnouncedTrustAnchorsInTsl(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    initialStateWithAlternativeTemplate();

    updateTrustStore(
        "Try to import invalid trust anchor: offer a TSL announcing two trust - the first and"
            + " second alternative - anchors at the same time, but without alternative CAs.",
        newTslGenerator("announceTwoAlternativeTrustAnchors")
            .getStandardTslDownload(CreateTslTemplate.defectTrustAnchorChangeTwoEntriesTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    // ---------------------------------------------------------------------------------
    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and the first alternative TSL signer certificate.",
        "alternativeFirstTrustAnchor",
        CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
        TslGenerator.alternativeTslSignerP12Path);

    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and the second alternative TSL signer certificate.",
        "alternativeSecondTrustAnchor",
        CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
        TslGenerator.alternativeSecondTslSignerP12Path);

    // ---------------------------------------------------------------------------------
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
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
  void verifyNewTrustAnchorsIsBroken(final TestInfo testInfo) {

    testCaseMessage(testInfo);

    initialStateWithAlternativeTemplate();

    log.info("Announce new trust anchor, TSL signer CA is broken");
    updateTrustStore(
        "Try to import invalid trust anchor:  offer of a TSL (without alternative CAs) announcing a"
            + " new trust anchor that has broken ASN.1 certificate structure.",
        newTslGenerator("brokenTrustAnchor")
            .getStandardTslDownload(CreateTslTemplate.defectTrustAnchorChangeBrokenTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    updateTrustStore(
        "Offer the default TSL.",
        newTslGenerator("default").getStandardTslDownload(CreateTslTemplate.defaultTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), USECASE_VALID));
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
      final int testOrder, final TestInfo testInfo) {

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

  protected TslOperation newActivationTimeTslOperation(
      @NonNull final Path tslSignerPath, @NonNull final ZonedDateTime newActivationTime) {

    return tslContainer -> {
      final TrustStatusListType tsl = tslContainer.getAsTsl();

      TslModifier.modifyStatusStartingTime(
          tsl,
          PkitsConstants.GEMATIK_TEST_TSP,
          TslConstants.STI_SRV_CERT_CHANGE,
          null,
          newActivationTime);

      return newTslGenerator().signTslOperation(tslSignerPath).apply(tsl);
    };
  }

  private void verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = GemLibPkiUtils.now().plusSeconds(tripleTslDownloadTime);

    log.info(STARTINGSTATUSTIME_ANNOUNCED_TA_MESSAGE, newActivationTime);

    updateTrustStore(
        "Offer a TSL without alternative test CAs and with announcement of a new trust anchor to be"
            + " activated after next 3 TSL downloads.",
        newTslGenerator(
                "announceFirstAlternativeTrustAnchorWithActivationTime3TslDownload",
                newActivationTimeTslOperation(defaultTslSigner, newActivationTime))
            .getStandardTslDownload(
                CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    // ---------------------------------------------------------------------------------
    try {
      updateTrustStore(
          "Try to import invalid trust anchor - too early: Offer a TSL with alternative CAs and the"
              + " TSL signer certificate from the new trust anchor. Trust anchor is not yet"
              + " active.",
          newTslGenerator("alternativeFirstTrustAnchorWithAlternativeCAs")
              .getStandardTslDownload(
                  CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                  TslGenerator.alternativeTslSignerP12Path),
          OCSP_REQUEST_IGNORE,
          withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));
    } catch (final Exception e) {
      // TODO integrate this fallback into tryToImportAnnouncedInvalidTrustAnchor around
      //      useCaseWithCert

      fallBackFromAlternativeToDefaultTrustAnchorAndCheck(TslGenerator.alternativeTslSignerP12Path);
      Assertions.fail(
          "a trust anchor was unexpectedly imported into the test object - a fallback was performed"
              + " to switch to the default trust anchor");
    }
    // ---------------------------------------------------------------------------------

    waitWithExtraSeconds(tripleTslDownloadTime);
    log.info(
        "new trust anchor should be activated now - StartingStatusTime: {}", newActivationTime);
    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and TSL signer certificate from the standard trust"
            + " space.",
        "defaultTrustAnchorWithAlternativeCAs",
        CreateTslTemplate.alternativeTsl(),
        defaultTslSigner);

    // ---------------------------------------------------------------------------------

    updateTrustStore(
        "Offer a TSL with alternative CAs and TSL signer certificate from the new trust"
            + " anchor. Trust anchor should be active.",
        newTslGenerator("alternativeFirstTrustAnchorWithAlternativeCAs")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                TslGenerator.alternativeTslSignerP12Path),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    fallBackFromAlternativeToDefaultTrustAnchorAndCheck(TslGenerator.alternativeTslSignerP12Path);
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

  private void verifyOverwriteAnnouncedInactiveTrustAnchor(final TestInfo testInfo) {

    testCaseMessage(testInfo);
    initialState();

    final ZonedDateTime now = GemLibPkiUtils.now();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = now.plusSeconds(tripleTslDownloadTime);

    log.info(STARTINGSTATUSTIME_ANNOUNCED_TA_MESSAGE, newActivationTime);
    updateTrustStore(
        "Announce first new trust anchor (TA1): Offer a TSL without alternative test CAs and with"
            + " announcement of a new trust anchor. Activation time: 3 x TSL download interval.",
        newTslGenerator("announceFirstAlternativeTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(
                    newActivationTime)),
        OCSP_REQUEST_EXPECT,
        WITHOUT_USECASE);

    // ---------------------------------------------------------------------------------

    final long tripleTslDownloadTimeM10 = tripleTslDownloadTime - 10;
    if (tripleTslDownloadTimeM10 < 0) {
      // TODO implement fallback
      log.error("activation of new trust anchor is in the past (too early)");
    }
    final ZonedDateTime newActivationTime2 = now.plusSeconds(tripleTslDownloadTimeM10);
    log.info(STARTINGSTATUSTIME_ANNOUNCED_TA_MESSAGE, newActivationTime2);

    updateTrustStore(
        "Announce first new trust anchor (TA2): Offer a TSL without alternative test CAs and with"
            + " announcement of another new trust anchor. Activation time: (3 x TSL download"
            + " interval) - 10 seconds.",
        newTslGenerator("announceAlternativeSecondTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(
                    newActivationTime2)),
        OCSP_REQUEST_EXPECT,
        WITHOUT_USECASE);
    // ---------------------------------------------------------------------------------

    waitWithExtraSeconds(tripleTslDownloadTime);

    log.info(
        "new trust anchor should be activated now - StartingStatusTime: {}", newActivationTime2);

    log.info(
        "Try to use first new trust anchor TA1 (must not be in the truststore of the test object)");
    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and TSL signer certificate from the first new trust"
            + " anchor.",
        "alternativeFirstTrustAnchorWithAlternativeCAs",
        CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
        TslGenerator.alternativeTslSignerP12Path);

    log.info(
        "Try to use second new trust anchor TA2 (should be in the truststore of the test object)");

    updateTrustStore(
        "Offer a TSL with alternative CAs and TSL signer certificate from the second"
            + " (alternative) new trust anchor.",
        newTslGenerator("alternativeSecondTrustAnchorWithAlternativeCAs")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl(),
                TslGenerator.alternativeSecondTslSignerP12Path),
        OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    // ---------------------------------------------------------------------------------

    updateTrustStore(
        getSwitchMessage(TA_NAME_ALT2, TA_NAME_DEFAULT),
        newTslGenerator("fallbackFromAlternativeSecondTrustAnchorToDefault")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl(),
                TslGenerator.alternativeSecondTslSignerP12Path),
        OCSP_REQUEST_EXPECT,
        WITHOUT_USECASE);

    try {

      useCaseWithCert(
          getPathOfFirstValidCert(),
          USECASE_VALID,
          OCSP_RESP_WITH_PROVIDED_CERT,
          OCSP_REQUEST_EXPECT);

    } catch (final Exception e) {
      log.error(
          "failed to execute use case: very likely because of wrong trust anchor in test object",
          e);
      fallBackFromAlternativeToDefaultTrustAnchorAndCheck(TslGenerator.alternativeTslSignerP12Path);
      Assertions.fail(
          "a trust anchor was unexpectedly imported into the test object - a fallback was performed"
              + " to switch to the default trust anchor");
    }
  }
}
