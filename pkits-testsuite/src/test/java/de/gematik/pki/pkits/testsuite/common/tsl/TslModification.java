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

package de.gematik.pki.pkits.testsuite.common.tsl;

import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.pkits.common.PkiCommonException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.time.ZonedDateTime;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

@Getter
@Builder
public class TslModification {

  private final int sequenceNr;
  private final String tspName;
  private final String newSsp;
  private final String tslDownloadUrlPrimary;
  private final String tslDownloadUrlBackup;
  private final ZonedDateTime issueDate;
  private final ZonedDateTime nextUpdate;
  private final int daysUntilNextUpdate;

  public void modify(@NonNull final TrustStatusListType tsl) throws DatatypeConfigurationException {

    if (nextUpdate == null) {
      if (daysUntilNextUpdate <= 0) {
        throw new PkiCommonException(
            "TslModification must contain nextUpdate or daysUntilNextUpdate.");
      } else {
        TslModifier.modifyIssueDateAndRelatedNextUpdate(tsl, issueDate, daysUntilNextUpdate);
      }
    } else {
      TslModifier.modifyIssueDate(tsl, issueDate);
      TslModifier.modifyNextUpdate(tsl, nextUpdate);
    }

    tsl.setId(TslModifier.generateTslId(sequenceNr, issueDate));
    // TODO count number of modified entries and log.debug them
    TslModifier.modifySequenceNr(tsl, sequenceNr);
    TslModifier.modifySspForCAsOfTsp(tsl, tspName, newSsp);
    TslModifier.modifyTslDownloadUrlPrimary(tsl, tslDownloadUrlPrimary);
    TslModifier.modifyTslDownloadUrlBackup(tsl, tslDownloadUrlBackup);
  }
}
