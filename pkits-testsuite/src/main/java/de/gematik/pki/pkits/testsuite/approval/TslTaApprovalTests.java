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

import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.reporting.TestResultLoggerExtension;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.time.ZonedDateTime;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI TSL Trust Anchor approval tests.")
@Order(9)
class TslTaApprovalTests extends ApprovalTestsBase {

  private static final String STARTINGSTATUSTIME_ANNOUNCED_TA_MESSAGE =
      "StartingStatusTime of announced trust anchor: {}";

  private static final String ALTERNATIVE_FIRST_TRUST_ANCHOR_WITH_ALTERNATIVE_CAS =
      "alternativeFirstTrustAnchorWithAlternativeCAs";

  /** gematikId: UE_PKI_TC_0106_001 */
  @Test
  @Afo(
      afoId = "GS-A_4642",
      description = "TUC_PKI_001: Periodische Aktualisierung TI-Vertrauensraum - Schritt 5")
  @Afo(afoId = "GS-A_4643", description = "TUC_PKI_013: Import TI-Vertrauensanker aus TSL")
  @DisplayName("Test updating trust anchor")
  void verifyUpdateTrustAnchor() {

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
        getDefaultTslSignerP12());

    updateTrustStore(
        "Offer a TSL (with alternate test CAs), signed with the new (announced) first alternative"
            + " trust anchor.",
        newTslGenerator(ALTERNATIVE_FIRST_TRUST_ANCHOR_WITH_ALTERNATIVE_CAS)
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                getTslSignerP12(TslGenerator.alternativeTslSignerP12Path)),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID));

    fallBackFromFirstAlternativeToDefaultTrustAnchorAndCheck();
  }

  private void fallBackFromFirstAlternativeToDefaultTrustAnchorAndCheck() {

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - start");

    updateTrustStore(
        getSwitchMessage(TA_NAME_ALT1, TA_NAME_DEFAULT),
        newTslGenerator("fallbackFromAlternativeFirstTrustAnchorToDefault")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(),
                getTslSignerP12(TslGenerator.alternativeTslSignerP12Path)),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    log.info("fallBackFromAlternativeToDefaultTrustAnchorAndCheck - finish\n\n");
  }

  private void offerTslWithNewTaAndVerifyItWasNotImported(
      final String description,
      final String tslName,
      final TrustStatusListType tsl,
      final P12Container tslSignerP12) {

    log.info("Test if Trust Anchor was erroneously imported");
    log.info("offerTslWithNewTaAndVerifyItWasNotImported - start: tslName {}", tslName);

    updateTrustStore(
        description,
        newTslGenerator(tslName).getStandardTslDownload(tsl, tslSignerP12),
        OCSP_REQUEST_IGNORE,
        WITHOUT_USECASE);

    TestResultLoggerExtension.stopExecutionOfRemainingTests(
        "defect trust anchor imported in the test object - a fallback is not implemented yet -> all"
            + " further tests are inconclusive: "
            + PkitsTestSuiteUtils.getCallerTrace());

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_INVALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_DO_NOT_EXPECT);

    TestResultLoggerExtension.allowExecutionOfRemainingTests();

    log.info("offerTslWithNewTaAndVerifyItWasNotImported - finish.\n\n");
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
  void verifyNewTrustAnchorInvalidTime() {

    initialState();

    // ---------------------------------------------------------------------------------

    log.info("start case 1: verify new trust anchor expired");
    initialStateWithAlternativeTemplate();

    updateTrustStore(
        "Try to import invalid trust anchor: offer a valid TSL announcing a new trust anchor (but"
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
        getTslSignerP12(TslGenerator.tslSignerFromExpiredTrustAnchorP12Path));

    // ---------------------------------------------------------------------------------

    log.info("start case 2: verify new trust anchor not yet valid");
    initialStateWithAlternativeTemplate();
    updateTrustStore(
        "Try to import invalid trust anchor: offer a valid TSL announcing a new trust anchor (but"
            + " not yet valid).",
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
        getTslSignerP12(TslGenerator.tslSignerFromNotYetValidTrustAnchorP12Path));

    // ---------------------------------------------------------------------------------
    log.info("case 3: TA with begin of StatusStartingTime expired");
    initialStateWithAlternativeTemplate();
    updateTrustStore(
        "Try to import valid trust anchor: offer a valid TSL announcing a new valid trust anchor,"
            + " that expires with the beginning of the StatusStartingTime.",
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
  void verifyMultipleAnnouncedTrustAnchorsInTsl() {

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
        getTslSignerP12(TslGenerator.alternativeTslSignerP12Path));

    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and the second alternative TSL signer certificate.",
        "alternativeSecondTrustAnchor",
        CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
        getTslSignerP12(TslGenerator.alternativeSecondTslSignerP12Path));

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
  void verifyNewTrustAnchorsIsBroken() {

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
        newTslGenerator(TslGenerator.TSL_NAME_DEFAULT)
            .getStandardTslDownload(CreateTslTemplate.defaultTsl()),
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
      final int testOrder) {

    if (testOrder == 1) {
      log.info("execute test case verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor");
      verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor();
    } else {
      log.info("execute test case verifyOverwriteAnnouncedInactiveTrustAnchor");
      verifyOverwriteAnnouncedInactiveTrustAnchor();
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
      @NonNull final P12Container tslSignerP12, @NonNull final ZonedDateTime newActivationTime) {

    return tslContainer -> {
      final TrustStatusListType tsl = tslContainer.getAsTsl();

      TslModifier.modifyStatusStartingTime(
          tsl,
          PkitsConstants.GEMATIK_TEST_TSP,
          TslConstants.STI_SRV_CERT_CHANGE,
          null,
          newActivationTime);

      return newTslGenerator().signTslOperation(tslSignerP12).apply(tsl);
    };
  }

  private void verifyHandlingOfStatusStartingTimeOfAnnouncedTrustAnchor() {

    initialState();

    final long tripleTslDownloadTime = getTripleTslDownloadTime();
    final ZonedDateTime newActivationTime = GemLibPkiUtils.now().plusSeconds(tripleTslDownloadTime);

    log.info(STARTINGSTATUSTIME_ANNOUNCED_TA_MESSAGE, newActivationTime);

    updateTrustStore(
        "Offer a TSL without alternative test CAs and with announcement of a new trust anchor to be"
            + " activated after next 3 TSL downloads.",
        newTslGenerator(
                "announceFirstAlternativeTrustAnchorWithActivationTime3TslDownload",
                newActivationTimeTslOperation(getDefaultTslSignerP12(), newActivationTime))
            .getStandardTslDownload(
                CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(
            getPathOfAlternativeCertificate(), USECASE_INVALID, OCSP_REQUEST_DO_NOT_EXPECT));

    // ---------------------------------------------------------------------------------

    TestResultLoggerExtension.stopExecutionOfRemainingTests(
        "defect trust anchor imported in the test object - a fallback is not implemented yet -> all"
            + " further tests are inconclusive: "
            + PkitsTestSuiteUtils.getCallerTrace());

    updateTrustStore(
        "Try to import invalid trust anchor - too early: Offer a TSL with alternative CAs and the"
            + " TSL signer certificate from the new trust anchor. Trust anchor is not yet"
            + " active.",
        newTslGenerator(ALTERNATIVE_FIRST_TRUST_ANCHOR_WITH_ALTERNATIVE_CAS)
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                getTslSignerP12(TslGenerator.alternativeTslSignerP12Path)),
        OCSP_REQUEST_IGNORE,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_INVALID));

    TestResultLoggerExtension.allowExecutionOfRemainingTests();
    // ---------------------------------------------------------------------------------

    waitWithExtraSeconds(tripleTslDownloadTime);
    log.info(
        "new trust anchor should be activated now - StartingStatusTime: {}", newActivationTime);
    offerTslWithNewTaAndVerifyItWasNotImported(
        "Offer a TSL with alternative CAs and TSL signer certificate from the standard trust"
            + " space.",
        "defaultTrustAnchorWithAlternativeCAs",
        CreateTslTemplate.alternativeTsl(),
        getDefaultTslSignerP12());

    // ---------------------------------------------------------------------------------

    updateTrustStore(
        "Offer a TSL with alternative CAs and TSL signer certificate from the new trust"
            + " anchor. Trust anchor should be active.",
        newTslGenerator(ALTERNATIVE_FIRST_TRUST_ANCHOR_WITH_ALTERNATIVE_CAS)
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                getTslSignerP12(TslGenerator.alternativeTslSignerP12Path)),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    fallBackFromFirstAlternativeToDefaultTrustAnchorAndCheck();
  }

  private static long getTripleTslDownloadTime() {
    // NOTE in case of timing problems consider to add ocspProcessingTimeSeconds
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

  private void verifyOverwriteAnnouncedInactiveTrustAnchor() {

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
        ALTERNATIVE_FIRST_TRUST_ANCHOR_WITH_ALTERNATIVE_CAS,
        CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
        getTslSignerP12(TslGenerator.alternativeTslSignerP12Path));

    log.info(
        "Try to use second new trust anchor TA2 (should be in the truststore of the test object)");

    updateTrustStore(
        "Offer a TSL with alternative CAs and TSL signer certificate from the second"
            + " (alternative) new trust anchor.",
        newTslGenerator("alternativeSecondTrustAnchorWithAlternativeCAs")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl(),
                getTslSignerP12(TslGenerator.alternativeSecondTslSignerP12Path)),
        OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    // ---------------------------------------------------------------------------------

    updateTrustStore(
        getSwitchMessage(TA_NAME_ALT2, TA_NAME_DEFAULT),
        newTslGenerator("fallbackFromAlternativeSecondTrustAnchorToDefault")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl(),
                getTslSignerP12(TslGenerator.alternativeSecondTslSignerP12Path)),
        OCSP_REQUEST_EXPECT,
        WITHOUT_USECASE);

    TestResultLoggerExtension.stopExecutionOfRemainingTests(
        "defect trust anchor was very likely imported in the test object - a fallback is not"
            + " implemented yet -> all further tests are inconclusive: "
            + PkitsTestSuiteUtils.getCallerTrace());
    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
    TestResultLoggerExtension.allowExecutionOfRemainingTests();
  }
}
