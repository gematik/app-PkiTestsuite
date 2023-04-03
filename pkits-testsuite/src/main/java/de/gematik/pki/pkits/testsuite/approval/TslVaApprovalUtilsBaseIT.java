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

import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_VALIDITY_CHECK_ENABLED;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import java.io.IOException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class TslVaApprovalUtilsBaseIT extends ApprovalTestsBaseIT {

  final Path alternativeTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-9-TEST-ONLY.p12");

  final Path alternativeSecondTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-16-TEST-ONLY.p12");

  final Path tslSignerFromExpiredTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_expired_ta.p12");

  protected enum OcspSeqNrUpdateMode {
    UPDATE_OCSP_SEQ_NR,
    DO_NOT_UPDATE_OCSP_SEQ_NR
  }

  private void setNewActivationTime(
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

  protected void importNewValidTrustAnchor(
      @NonNull final Path tslTemplate,
      @NonNull final Path tslSignerPath,
      final ZonedDateTime newActivationTime,
      final OcspSeqNrUpdateMode ocspSeqNrUpdateMode)
      throws DatatypeConfigurationException, IOException {

    log.info("importNewValidTrustAnchor - start: tsl template {}", tslTemplate);

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

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

    printCurrentTslSeqNr();
    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(offeredSeqNr, getExpectedOcspTslSeqNr());
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);

    if (ocspSeqNrUpdateMode == OcspSeqNrUpdateMode.UPDATE_OCSP_SEQ_NR) {
      setExpectedOcspTslSeqNr(tslSequenceNr.getExpectedNrInTestObject());
    }

    log.info("importNewValidTrustAnchor - finish\n\n");
  }
}
