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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.time.ZonedDateTime;

public class ModifyIssueDateAndRelatedNextUpdateTslOperation implements TslOperation {

  private final ZonedDateTime issueDate;
  private final ZonedDateTime nextUpdate;
  private final int daysUntilNextUpdate;

  public ModifyIssueDateAndRelatedNextUpdateTslOperation(
      final ZonedDateTime issueDate,
      final ZonedDateTime nextUpdate,
      final int daysUntilNextUpdate) {
    this.issueDate = issueDate;
    this.nextUpdate = nextUpdate;
    this.daysUntilNextUpdate = daysUntilNextUpdate;

    if ((nextUpdate == null) && (daysUntilNextUpdate <= 0)) {
      throw new PkiCommonException(
          "ModifyIssueDateAndRelatedNextUpdateTslOperation must contain nextUpdate or"
              + " daysUntilNextUpdate.");
    }
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    final TrustStatusListType tsl = tslContainer.getAsTsl();

    if (nextUpdate == null) {
      TslModifier.modifyIssueDateAndRelatedNextUpdate(tsl, issueDate, daysUntilNextUpdate);
    } else {
      TslModifier.modifyIssueDate(tsl, issueDate);
      TslModifier.modifyNextUpdate(tsl, nextUpdate);
    }

    return new TslContainer(tsl);
  }
}
