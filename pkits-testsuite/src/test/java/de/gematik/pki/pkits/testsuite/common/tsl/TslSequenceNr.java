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

import static de.gematik.pki.pkits.testsuite.common.TestsuiteConstants.TSL_SEQNR_FILE_PATH;

import de.gematik.pki.pkits.testsuite.exceptions.TestsuiteException;
import java.io.IOException;
import java.nio.file.Files;
import lombok.Getter;

public final class TslSequenceNr {

  @Getter private int currentNrInTestobject = 1;
  @Getter private int expectedNrInTestobject = 1;

  private static TslSequenceNr instance;

  private TslSequenceNr() {
    assignCurrentNrInTestobject();
  }

  public void setExpectedNrInTestobject(final int offeredSeqNr) throws IOException {
    expectedNrInTestobject = offeredSeqNr;
    Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(offeredSeqNr));
  }

  public static TslSequenceNr getInstance() {
    if (instance == null) {
      instance = new TslSequenceNr();
    }
    return instance;
  }

  public TslSequenceNr assignCurrentNrInTestobject() {
    if (Files.exists(TSL_SEQNR_FILE_PATH)) {
      readTslSeqNrFromFile();
    } else {
      writeTslSeqNrToFile(currentNrInTestobject);
    }
    return instance;
  }

  public void updateCurrentNrInTestobject(final int seqNr) {
    writeTslSeqNrToFile(seqNr);
  }

  private void writeTslSeqNrToFile(final int seqNr) {
    try {
      Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(seqNr));
      this.currentNrInTestobject = seqNr;
    } catch (final IOException e) {
      throw new TestsuiteException("Could not write TslSeqNr to file.", e);
    }
  }

  private void readTslSeqNrFromFile() {
    try {
      this.currentNrInTestobject = Integer.parseInt(Files.readString(TSL_SEQNR_FILE_PATH));
    } catch (final IOException e) {
      throw new TestsuiteException("Could not read TslSeqNr from file.", e);
    }
  }
}
