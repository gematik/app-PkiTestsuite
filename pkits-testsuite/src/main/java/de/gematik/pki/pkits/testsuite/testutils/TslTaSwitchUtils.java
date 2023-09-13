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

package de.gematik.pki.pkits.testsuite.testutils;

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.ALTERNATIVE_SECOND_TRUST_ANCHOR;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.DEFAULT_TSL_SIGNER;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.ALTERNATIVE_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase.ClientCertsConfig.DEFAULT_CLIENT_CERTS_CONFIG;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslDownloadGenerator.TSL_NAME_DEFAULT;
import static de.gematik.pki.pkits.testsuite.usecases.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslDownloadGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.security.cert.X509Certificate;
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
        DEFAULT_TSL_SIGNER,
        DEFAULT_TRUST_ANCHOR,
        true);

    updateTrustStore(
        "Offer a TSL (with alternate test CAs), signed with the new (announced) first alternative"
            + " trust anchor.",
        newTslDownloadGenerator("firstAlternativeTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(),
                getTslSignerP12(TslDownloadGenerator.alternativeTslSignerP12Path),
                ALTERNATIVE_FIRST_TRUST_ANCHOR),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, UseCaseResult.USECASE_VALID));
  }

  @Test
  @Order(102)
  void switchFromAlternativeFirstToDefault() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_ALT1, TA_NAME_DEFAULT),
        "trustAnchorChangeFromAlternative1ToDefault",
        CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(),
        getTslSignerP12(TslDownloadGenerator.alternativeTslSignerP12Path),
        ALTERNATIVE_FIRST_TRUST_ANCHOR,
        false);

    updateTrustStore(
        OFFER_DEFAULT_TSL_MESSAGE,
        newTslDownloadGenerator(TSL_NAME_DEFAULT)
            .getStandardTslDownload(CreateTslTemplate.defaultTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(DEFAULT_CLIENT_CERTS_CONFIG, UseCaseResult.USECASE_VALID));
  }

  @Test
  @Order(103)
  void switchFromDefaultToAlternativeSecond() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_DEFAULT, TA_NAME_ALT2),
        "trustAnchorChangeFromDefaultToAlternative2",
        CreateTslTemplate.trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(
            GemLibPkiUtils.now()),
        DEFAULT_TSL_SIGNER,
        DEFAULT_TRUST_ANCHOR,
        true);

    updateTrustStore(
        "Offer a TSL with alternative CAs and TSL signer certificate from the second"
            + " (alternative) new trust anchor.",
        newTslDownloadGenerator("secondAlternativeTrustAnchor")
            .getStandardTslDownload(
                CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl(),
                getTslSignerP12(TslDownloadGenerator.alternativeSecondTslSignerP12Path),
                ALTERNATIVE_SECOND_TRUST_ANCHOR),
        OCSP_REQUEST_EXPECT,
        withUseCase(ALTERNATIVE_CLIENT_CERTS_CONFIG, UseCaseResult.USECASE_VALID));
  }

  @Test
  @Order(104)
  void switchFromAlternativeSecondToDefault() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_ALT2, TA_NAME_DEFAULT),
        "trustAnchorChangeFromAlternative2ToDefault",
        CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl(),
        getTslSignerP12(TslDownloadGenerator.alternativeSecondTslSignerP12Path),
        ALTERNATIVE_SECOND_TRUST_ANCHOR,
        false);

    updateTrustStore(
        OFFER_DEFAULT_TSL_MESSAGE,
        newTslDownloadGenerator(TslDownloadGenerator.TSL_NAME_DEFAULT)
            .getStandardTslDownload(CreateTslTemplate.defaultTsl()),
        OCSP_REQUEST_EXPECT,
        withUseCase(DEFAULT_CLIENT_CERTS_CONFIG, UseCaseResult.USECASE_VALID));
  }

  void switchTrustAnchor(
      final String description,
      final String tslName,
      final TrustStatusListType tsl,
      final P12Container tslSignerP12,
      final X509Certificate trustAnchor,
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
        newTslDownloadGenerator(tslName).getStandardTslDownload(tsl, tslSignerP12, trustAnchor),
        OCSP_REQUEST_EXPECT,
        WITHOUT_USECASE);

    log.info("switchTrustAnchor\n\n");
  }
}
