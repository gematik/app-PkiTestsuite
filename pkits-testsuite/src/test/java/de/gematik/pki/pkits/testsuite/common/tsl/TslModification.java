/*
 * Copyright (c) 2022 gematik GmbH
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

import java.time.ZonedDateTime;
import lombok.Builder;
import lombok.Getter;

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
}
