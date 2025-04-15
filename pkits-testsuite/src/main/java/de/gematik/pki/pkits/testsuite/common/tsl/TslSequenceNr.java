/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.testsuite.common.tsl;

import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.TSL_SEQNR_FILE_PATH;

import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.IOException;
import java.nio.file.Files;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
public final class TslSequenceNr {

  // the sequence number of the tsl that is actually active inside the test object
  private int currentNrInTestObject = 1;

  // the sequence number of the tsl we expect to be active inside the test object
  @Setter private int expectedNrInTestObject = 1;

  // last sequence number of the tsl that was offered for downloaded to the test object
  private int lastOfferedTslSeqNr = 0;

  private static TslSequenceNr instance;

  public static synchronized TslSequenceNr getInstance() {
    if (instance == null) {
      instance = new TslSequenceNr();
    }
    return instance;
  }

  private TslSequenceNr() {
    initializeCurrentTslSeqNr();
  }

  private void readTslSeqNrFromFile() {
    try {
      this.currentNrInTestObject = Integer.parseInt(Files.readString(TSL_SEQNR_FILE_PATH));
    } catch (final IOException | NumberFormatException e) {
      final String message = "Cannot not read TslSeqNr from file: " + TSL_SEQNR_FILE_PATH;
      log.error(message, e);
      throw new TestSuiteException(message, e);
    }
  }

  public TslSequenceNr initializeCurrentTslSeqNr() {
    if (Files.exists(TSL_SEQNR_FILE_PATH)) {
      readTslSeqNrFromFile();
    } else {
      saveCurrentTestObjectTslSeqNr(currentNrInTestObject);
    }
    return instance;
  }

  public void setLastOfferedTslSeqNr(final int offeredTslSeqNr) {
    lastOfferedTslSeqNr = offeredTslSeqNr;
    persistTslSeqNr(lastOfferedTslSeqNr);
  }

  private void persistTslSeqNr(final int tslSeqNr) {
    try {
      Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(tslSeqNr));
    } catch (final IOException e) {
      throw new TestSuiteException("Cannot write sequence number file!", e);
    }
  }

  public void saveCurrentTestObjectTslSeqNr(final int tslSeqNr) {
    persistTslSeqNr(tslSeqNr);
    this.currentNrInTestObject = tslSeqNr;
  }

  public int getNextTslSeqNr() {
    if (lastOfferedTslSeqNr == 0) {
      return getCurrentNrInTestObject() + 1;
    }
    return lastOfferedTslSeqNr + 1;
  }

  @Override
  public String toString() {
    return "TslSequenceNr{currentNrInTestObject=%d, lastOfferedTslSeqNr=%d, expectedNrInTestObject=%d}"
        .formatted(currentNrInTestObject, lastOfferedTslSeqNr, expectedNrInTestObject);
  }
}
