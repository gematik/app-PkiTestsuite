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
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_INVALID;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;

import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload.ClearConfigAfterWaiting;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.reporting.TestResultLoggerExtension;
import de.gematik.pki.pkits.tsl.provider.api.TslDownloadEndpointType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.function.BiFunction;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
@DisplayName("Additional PKI TSL approval tests.")
@Order(10)
class TslApprovalExtraTests extends ApprovalTestsBase {

  final BiFunction<ZonedDateTime, ZonedDateTime, TslOperation> rewriteIssueDateAndNextUpdate =
      (newIssueDate, newNextUpdate) ->
          tslContainer -> {
            final TrustStatusListType tsl = tslContainer.getAsTsl();

            tsl.getSchemeInformation()
                .setListIssueDateTime(TslModifier.getXmlGregorianCalendar(newIssueDate));

            tsl.getSchemeInformation()
                .getNextUpdate()
                .setDateTime(TslModifier.getXmlGregorianCalendar(newNextUpdate));

            return newTslGenerator().signTslOperation(getDefaultTslSignerP12()).apply(tsl);
          };

  /** gematikId: UE_PKI_TC_0103_002 */
  @Test
  @Afo(afoId = "GS-A_4642", description = "TUC_PKI_001: Prüfung der Aktualität der TSL - Schritt 2")
  @Afo(afoId = "GS-A_4648", description = "TUC_PKI_019: Prüfung der Aktualität der TSL - Schritt 7")
  @DisplayName(
      "Expired TSL in system (NextUpdate is outside the TSL Grace Period). WARNING: After the"
          + " test a TSL must then be manually inserted into the system.")
  void verifyExpiredTslInSystem() {

    initialState();

    final int tslGracePeriodDays = testSuiteConfig.getTestObject().getTslGracePeriodDays();

    Assumptions.assumeTrue(
        tslGracePeriodDays == 0, "Case 1 (tslGracePeriodDays > 0) is not implemented yet.");

    waitForOcspCacheToExpire();

    log.info("case 2: nextUpdate is outside TSL Grace Period");
    final int timeForTslUpdateAndUseCaseMinutes = 1;

    final ZonedDateTime newIssueDate =
        GemLibPkiUtils.now()
            .minus(30, ChronoUnit.DAYS)
            .plus(timeForTslUpdateAndUseCaseMinutes, ChronoUnit.MINUTES);

    final ZonedDateTime newNextUpdate =
        GemLibPkiUtils.now()
            .minus(tslGracePeriodDays, ChronoUnit.DAYS)
            .plus(timeForTslUpdateAndUseCaseMinutes, ChronoUnit.MINUTES);

    final TslDownload tslDownload =
        newTslGenerator(
                "nextUpdateInPastOutsideGracePeriod",
                rewriteIssueDateAndNextUpdate.apply(newIssueDate, newNextUpdate))
            .getStandardTslDownload(CreateTslTemplate.defaultTsl());

    final String testResultsMessage =
        "Now, the product type does not have a valid trust space after the test and should neither"
            + " be able to perform a TSL update nor accept connections. A new valid TSL must then"
            + " be manually inserted into the system.\n";

    TestResultLoggerExtension.stopExecutionOfRemainingTests(
        testResultsMessage + PkitsTestSuiteUtils.getCallerTrace());

    updateTrustStore(
        "Offer a TSL with default CAs and with NextUpdate just about to expire - NextUpdate is set"
            + " to TSL Grace Period minus "
            + timeForTslUpdateAndUseCaseMinutes
            + " minutes.",
        tslDownload,
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), USECASE_VALID, OCSP_REQUEST_EXPECT));

    log.info(
        "wait for the TSL guaranteed to expire: {} minutes", timeForTslUpdateAndUseCaseMinutes);
    final int timeForTslUpdateAndUseCaseSeconds = timeForTslUpdateAndUseCaseMinutes * 60;
    PkitsCommonUtils.waitSeconds(timeForTslUpdateAndUseCaseSeconds);
    log.info("waiting is over");

    log.info(
        "Offer the same TSL (with default CAs and with NextUpdate just about to expire)."
            + " VALIDITY_WARNING_2 (TSL_GRACE_PERIOD expired, TSL is not valid anymore) is expected"
            + " in the Test Object.");

    tslDownload.configureOcspResponderForTslSigner();
    tslDownload.waitForTslDownload(
        tslSequenceNr.getExpectedNrInTestObject(),
        TslDownloadEndpointType.ANY_ENDPOINT,
        ClearConfigAfterWaiting.CLEAR_CONFIG);
    tslDownload.waitUntilOcspRequestForSignerOptional();

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_INVALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_DO_NOT_EXPECT);

    log.warn(testResultsMessage);
  }
}
