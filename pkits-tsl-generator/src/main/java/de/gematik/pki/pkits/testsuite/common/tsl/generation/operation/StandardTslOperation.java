/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import java.time.ZonedDateTime;
import lombok.Builder;
import lombok.Getter;

@Getter
public class StandardTslOperation extends AggregateTslOperation {

  private final StandardTslOperationConfig config;

  @Getter
  @Builder
  public static class StandardTslOperationConfig {
    private int tslSeqNr;
    private String tspName;
    private String newSsp;
    private String tslDownloadUrlPrimary;
    private String tslDownloadUrlBackup;
    private ZonedDateTime issueDate;
    private ZonedDateTime nextUpdate;
    private int daysUntilNextUpdate;
  }

  public StandardTslOperation(final StandardTslOperationConfig config) {
    this.config = config;
    add(
        new ModifyIssueDateAndRelatedNextUpdateTslOperation(
            config.issueDate, config.nextUpdate, config.daysUntilNextUpdate));
    add(new ModifyTslIdTslOperation(config.tslSeqNr, config.issueDate));
    add(new ModifyTslSeqNrTslOperation(config.tslSeqNr));
    add(new ModifySspForCAsOfTspTslOperation(config.tspName, config.newSsp));
    add(new ModifyPrimaryUrlTslOperation(config.tslDownloadUrlPrimary));
    add(new ModifyBackupUrlTslOperation(config.tslDownloadUrlBackup));
  }
}
