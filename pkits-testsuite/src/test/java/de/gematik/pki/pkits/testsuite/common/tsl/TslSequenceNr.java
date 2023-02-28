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

import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.TSL_SEQNR_FILE_PATH;

import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.IOException;
import java.nio.file.Files;
import lombok.Getter;
import lombok.Setter;

public final class TslSequenceNr {

  // the sequence number of the tsl that is actually active inside the test object
  // TODO ablösen und nur noch lastOffered nehmen, uns muss nur am Anfang interessieren, welche TSL
  // im TO ist.
  @Getter private int currentNrInTestObject = 1;

  // the sequence number of the tsl we expect to be active inside the test object
  @Getter @Setter private int expectedNrInTestObject = 1;

  // last sequence number of the tsl that was offered for downloaded to the test object
  @Getter private int lastOfferedNr = 0;

  private static TslSequenceNr instance;

  public static TslSequenceNr getInstance() {
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
    } catch (final IOException e) {
      throw new TestSuiteException("Could not read TslSeqNr from file.", e);
    }
  }

  public TslSequenceNr initializeCurrentTslSeqNr() {
    if (Files.exists(TSL_SEQNR_FILE_PATH)) {
      readTslSeqNrFromFile();
    } else {
      saveCurrentTestObjectSeqNr(currentNrInTestObject);
    }
    return instance;
  }

  public void setLastOfferedNr(final int offeredSeqNr) {
    lastOfferedNr = offeredSeqNr;
    try { // todo write seqNr Methode einführen
      Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(offeredSeqNr));
    } catch (final IOException e) {
      throw new TestSuiteException("Cannot write sequence number file!", e);
    }
  }

  public void saveCurrentTestObjectSeqNr(final int seqNr) {
    try {
      Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(seqNr));
      this.currentNrInTestObject = seqNr;
    } catch (final IOException e) {
      throw new TestSuiteException("Could not write TslSeqNr to file.", e);
    }
  }

  public int getNextTslSeqNr() {
    if (lastOfferedNr == 0) {
      return getCurrentNrInTestObject() + 1;
    }
    return lastOfferedNr + 1;
  }

  @Override
  public String toString() {
    return "TslSequenceNr{currentNrInTestObject=%d, lastOfferedNr=%d, expectedNrInTestObject=%d}"
        .formatted(currentNrInTestObject, lastOfferedNr, expectedNrInTestObject);
  }
}
