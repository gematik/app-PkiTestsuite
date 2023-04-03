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
import java.io.IOException;
import java.nio.file.Path;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

@Slf4j
class TslVaSwitchUtils extends TslVaApprovalUtilsBaseIT {

  @Test
  @Order(101)
  void switchFromDefaultToAlternativeFirst() throws DatatypeConfigurationException, IOException {

    switchTrustAnchor(TslVaApprovalTestsIT.tslTemplateTrustAnchorChange, defaultTslSigner, true);

    updateTrustStore(
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchorAlternativeCa,
        alternativeTslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);
  }

  @Test
  @Order(102)
  void switchFromAlternativeFirstToDefault() throws DatatypeConfigurationException, IOException {
    switchTrustAnchor(
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchorTrustAnchorChange,
        alternativeTslSignerP12Path,
        false);

    updateTrustStore(
        tslSettings.getDefaultTemplate(),
        defaultTslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfFirstValidCert(),
        USECASE_VALID);
  }

  @Test
  @Order(103)
  void switchFromDefaultToAlternativeSecond() throws DatatypeConfigurationException, IOException {
    switchTrustAnchor(
        TslVaApprovalTestsIT.tslTemplateTrustAnchorChangeAlternativeTrustAnchor2FutureShort,
        defaultTslSigner,
        true);

    updateTrustStore(
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchor2AlternativeCa,
        alternativeSecondTslSignerP12Path,
        OCSP_REQUEST_EXPECT,
        getPathOfAlternativeCertificate(),
        USECASE_VALID);
  }

  @Test
  @Order(104)
  void switchFromAlternativeSecondToDefault() throws DatatypeConfigurationException, IOException {
    switchTrustAnchor(
        TslVaApprovalTestsIT.tslTemplateAlternativeTrustAnchor2TrustAnchorChange,
        alternativeSecondTslSignerP12Path,
        false);

    updateTrustStore(
        tslSettings.getDefaultTemplate(),
        defaultTslSigner,
        OCSP_REQUEST_EXPECT,
        getPathOfFirstValidCert(),
        USECASE_VALID);
  }

  void switchTrustAnchor(
      final Path tslTemplate, final Path tslSignerP12Path, final boolean withInitialState)
      throws DatatypeConfigurationException, IOException {

    retrieveCurrentTslSeqNrInTestObject();
    if (withInitialState) {
      initialTslDownloadByTestObject();
    }
    log.info("tslSequenceNr after retrieveCurrentTslSeqNrInTestObject: {}", tslSequenceNr);
    tslSequenceNr.setExpectedNrInTestObject(tslSequenceNr.getCurrentNrInTestObject());
    log.info("update expectedNrInTestObject in tslSequenceNr: {}", tslSequenceNr);

    log.info(
        "switchTrustAnchor:\ntslTemplate {}\n, tslSignerP12Path {}", tslTemplate, tslSignerP12Path);

    importNewValidTrustAnchor(
        tslTemplate,
        tslSignerP12Path,
        GemLibPkiUtils.now(),
        OcspSeqNrUpdateMode.UPDATE_OCSP_SEQ_NR);

    log.info("switchTrustAnchor\n\n");
  }
}
