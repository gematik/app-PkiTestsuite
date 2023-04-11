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

import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_VALID;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.approval.support.OcspSeqNrUpdateMode;
import java.nio.file.Path;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
class TslVaSwitchUtils extends TslVaApprovalUtilsBaseIT {

  @Test
  @Order(101)
  void switchFromDefaultToAlternativeFirst() {

    switchTrustAnchor(
        getSwitchMessage(TA_NAME_DEFAULT, TA_NAME_ALT1),
        TslVaApprovalTestsIT.tslTemplateTrustAnchorChange,
        defaultTslSigner,
        true);

    updateTrustStore(
        "Offer a TSL (with alternate test CAs), signed with the new (announced) first alternative"
            + " trust anchor.",
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchorAlternativeCa,
        alternativeTslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);
  }

  @Test
  @Order(102)
  void switchFromAlternativeFirstToDefault() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_ALT1, TA_NAME_DEFAULT),
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchorTrustAnchorChange,
        alternativeTslSignerP12Path,
        false);

    updateTrustStore(
        "Offer the default TSL.",
        tslSettings.getDefaultTemplate(),
        defaultTslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfFirstValidCert(),
        USECASE_VALID);
  }

  @Test
  @Order(103)
  void switchFromDefaultToAlternativeSecond() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_DEFAULT, TA_NAME_ALT2),
        TslVaApprovalTestsIT.tslTemplateTrustAnchorChangeAlternativeTrustAnchor2FutureShort,
        defaultTslSigner,
        true);

    updateTrustStore(
        "Offer a TSL with alternative test CAs and TSL signer certificate from the second"
            + " (alternative) new trust anchor.",
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchor2AlternativeCa,
        alternativeSecondTslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);
  }

  @Test
  @Order(104)
  void switchFromAlternativeSecondToDefault() {
    switchTrustAnchor(
        getSwitchMessage(TA_NAME_ALT2, TA_NAME_DEFAULT),
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchor2TrustAnchorChange,
        alternativeSecondTslSignerP12Path,
        false);

    updateTrustStore(
        "Offer the default TSL.",
        tslSettings.getDefaultTemplate(),
        defaultTslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfFirstValidCert(),
        USECASE_VALID);
  }

  void switchTrustAnchor(
      final String description,
      final Path tslTemplate,
      final Path tslSignerP12Path,
      final boolean withInitialState) {

    retrieveCurrentTslSeqNrInTestObject();
    if (withInitialState) {
      initialTslDownloadByTestObject();
    }
    log.info("tslSequenceNr after retrieveCurrentTslSeqNrInTestObject: {}", tslSequenceNr);
    tslSequenceNr.setExpectedNrInTestObject(tslSequenceNr.getCurrentNrInTestObject());
    log.info("update expectedNrInTestObject in tslSequenceNr: {}", tslSequenceNr);

    log.info(
        "switchTrustAnchor:\ntslTemplate {}\n, tslSignerP12Path {}", tslTemplate, tslSignerP12Path);

    updateTrustStore(
        description,
        tslTemplate,
        tslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        null,
        SKIP_USECASE,
        null,
        getActivationTimeModifier(tslSignerP12Path, GemLibPkiUtils.now()),
        OcspSeqNrUpdateMode.UPDATE_OCSP_SEQ_NR);

    log.info("switchTrustAnchor\n\n");
  }
}
