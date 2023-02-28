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

package de.gematik.pki.pkits.testsuite.unittests;

import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.TSL_SEQNR_FILE_PATH;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.pkits.testsuite.common.tsl.TslSequenceNr;
import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class TslSequenceNrTest {

  /** Note: TslSequenceNr implements Singleton */
  @BeforeAll
  static void init() throws IOException {
    if (Files.exists(TSL_SEQNR_FILE_PATH)) {
      Files.delete(TSL_SEQNR_FILE_PATH);
    }
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();
    assertThat(tslSequenceNr).isNotNull();
    assertThat(tslSequenceNr.getCurrentNrInTestObject()).isEqualTo(1);
  }

  @Test
  void tslSeqNrIsAssignedFileExists() throws IOException {
    final int seqNr = 42;
    Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(seqNr));
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();
    assertThat(tslSequenceNr.initializeCurrentTslSeqNr().getCurrentNrInTestObject())
        .isEqualTo(seqNr);
    final int seqNrfromFile = Integer.parseInt(Files.readString(TSL_SEQNR_FILE_PATH));
    assertThat(seqNr).isEqualTo(seqNrfromFile);
  }
}
