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

package de.gematik.pki.pkits.testsuite.testutils;

import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator.TSL_NAME_DEFAULT;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
public class TslTaSwitchUtils extends ApprovalTestsBase {

  @Test
  @Order(101)
  void switchFromDefaultToAlternativeFirst() {

    switchTrustAnchor(
        getSwitchMessage(TA_NAME_DEFAULT, TA_NAME_ALT1),
        "trustAnchorChangeFromDefaultToAlternative1",
        CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(),
        getDefaultTslSignerP12(),
        true);

    updateTrustStore(
        "Offer a TSL (with alternate test CAs), signed with the new (announced) first alternative"
            + " trust anchor.",
        newTslGenerator("firstAlternativeTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                getTslSignerP12(TslGenerator.alternativeTslSignerP12Path)),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), UseCaseResult.USECASE_VALID));
  }

  @Test
  @Order(102)
  void switchFromAlternativeFirstToDefault() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_ALT1, TA_NAME_DEFAULT),
        "trustAnchorChangeFromAlternative1ToDefault",
        CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(),
        getTslSignerP12(TslGenerator.alternativeTslSignerP12Path),
        false);

    updateTrustStore(
        "Offer the default TSL.",
        newTslGenerator(TSL_NAME_DEFAULT).getStandardTslDownload(CreateTslTemplate.defaultTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), UseCaseResult.USECASE_VALID));
  }

  @Test
  @Order(103)
  void switchFromDefaultToAlternativeSecond() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_DEFAULT, TA_NAME_ALT2),
        "trustAnchorChangeFromDefaultToAlternative2",
        CreateTslTemplate.trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(
            GemLibPkiUtils.now()),
        getDefaultTslSignerP12(),
        true);

    updateTrustStore(
        "Offer a TSL with alternative CAs and TSL signer certificate from the second"
            + " (alternative) new trust anchor.",
        newTslGenerator("secondAlternativeTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl(),
                getTslSignerP12(TslGenerator.alternativeSecondTslSignerP12Path)),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfAlternativeCertificate(), UseCaseResult.USECASE_VALID));
  }

  @Test
  @Order(104)
  void switchFromAlternativeSecondToDefault() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_ALT2, TA_NAME_DEFAULT),
        "trustAnchorChangeFromAlternative2ToDefault",
        CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl(),
        getTslSignerP12(TslGenerator.alternativeSecondTslSignerP12Path),
        false);

    updateTrustStore(
        "Offer the default TSL.",
        newTslGenerator(TslGenerator.TSL_NAME_DEFAULT)
            .getStandardTslDownload(CreateTslTemplate.defaultTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(getPathOfFirstValidCert(), UseCaseResult.USECASE_VALID));
  }

  void switchTrustAnchor(
      final String description,
      final String tslName,
      final TrustStatusListType tsl,
      final P12Container tslSignerP12,
      final boolean withInitialState) {

    retrieveCurrentTslSeqNrInTestObject();

    log.info("tslSequenceNr after retrieveCurrentTslSeqNrInTestObject: {}", tslSequenceNr);
    tslSequenceNr.setExpectedNrInTestObject(tslSequenceNr.getCurrentNrInTestObject());
    log.info("update expectedNrInTestObject in tslSequenceNr: {}", tslSequenceNr);
    if (withInitialState) {
      initialTslDownloadByTestObject();
    }

    log.info("switchTrustAnchor:\ntslName {}\n, tslSignerP12Path {}", tslName, tslSignerP12);

    updateTrustStore(
        description,
        newTslGenerator(tslName).getStandardTslDownload(tsl, tslSignerP12),
        OCSP_REQUEST_EXPECT,
        WITHOUT_USECASE);

    log.info("switchTrustAnchor\n\n");
  }
}