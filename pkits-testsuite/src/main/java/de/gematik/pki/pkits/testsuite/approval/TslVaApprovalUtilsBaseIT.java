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

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.function.Consumer;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class TslVaApprovalUtilsBaseIT extends ApprovalTestsBaseIT {

  protected static final UseCaseResult SKIP_USECASE = null;
  final Path alternativeTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-9-TEST-ONLY.p12");

  final Path alternativeSecondTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-16-TEST-ONLY.p12");

  final Path tslSignerFromExpiredTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_expired_ta.p12");

  protected static final String TA_NAME_DEFAULT = "default";
  protected static final String TA_NAME_ALT1 = "first alternative";
  protected static final String TA_NAME_ALT2 = "second alternative";

  protected static String getSwitchMessage(final String anchorType1, final String anchorType2) {
    return "Offer a TSL to switch from the %s trust anchor to the %s trust anchor."
        .formatted(anchorType1, anchorType2);
  }

  Consumer<TslDownload> getActivationTimeModifier(
      final Path tslSignerPath, final ZonedDateTime newActivationTime) {
    return (tslDownload) -> {
      if (newActivationTime != null) {
        setNewActivationTime(tslDownload, tslSignerPath, newActivationTime);
      }
    };
  }

  private void setNewActivationTime(
      final TslDownload tslDownload,
      @NonNull final Path tslSignerPath,
      final ZonedDateTime newActivationTime) {

    byte[] tslBytes = tslDownload.getTslBytes();

    try {
      tslBytes =
          TslModifier.modifiedStatusStartingTime(
              tslBytes,
              PkitsConstants.GEMATIK_TEST_TSP,
              TslConstants.STI_SRV_CERT_CHANGE,
              null,
              newActivationTime);
    } catch (final DatatypeConfigurationException e) {
      throw new TestSuiteException("cannot modify TSL", e);
    }

    signAndSetTslBytes(tslDownload, tslSignerPath, tslBytes);
  }
}
