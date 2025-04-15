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
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

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
    final int tslSeqNr = 420000;
    Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(tslSeqNr));
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();

    assertThat(tslSequenceNr.initializeCurrentTslSeqNr().getCurrentNrInTestObject())
        .isEqualTo(tslSeqNr);

    final int tslSeqNrFromFile = Integer.parseInt(Files.readString(TSL_SEQNR_FILE_PATH));

    assertThat(tslSeqNr).isEqualTo(tslSeqNrFromFile);
  }

  @Test
  void testSetLastOfferedTslSeqNr() throws IOException {
    final int tslSeqNr = 420000;
    Files.writeString(TSL_SEQNR_FILE_PATH, String.valueOf(tslSeqNr));
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();

    final int newTslSeqNr = -2 * 420000;

    tslSequenceNr.setLastOfferedTslSeqNr(newTslSeqNr);

    assertThat(tslSequenceNr.getLastOfferedTslSeqNr()).isEqualTo(newTslSeqNr);
    final int tslSeqNrFromFile = Integer.parseInt(Files.readString(TSL_SEQNR_FILE_PATH));
    assertThat(tslSeqNrFromFile).isEqualTo(newTslSeqNr);
  }

  @Test
  void testSaveCurrentTestObjectTslSeqNrException() {
    final int tslSeqNr = 420000;
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();

    try (final MockedStatic<Files> filesMockedStatic =
        Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {

      filesMockedStatic
          .when(() -> Files.writeString(Mockito.any(), Mockito.any()))
          .thenThrow(new IOException());

      assertThatThrownBy(() -> tslSequenceNr.saveCurrentTestObjectTslSeqNr(tslSeqNr))
          .isInstanceOf(TestSuiteException.class)
          .hasMessage("Cannot write sequence number file!")
          .cause()
          .isInstanceOf(IOException.class);
    }
  }

  @Test
  void testInitializeCurrentTslSeqNrException() throws IOException {

    Files.writeString(TSL_SEQNR_FILE_PATH, "badTslSeqNr");
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();

    assertThatThrownBy(tslSequenceNr::initializeCurrentTslSeqNr)
        .isInstanceOf(TestSuiteException.class)
        .hasMessage("Cannot not read TslSeqNr from file: " + TSL_SEQNR_FILE_PATH)
        .cause()
        .isInstanceOf(NumberFormatException.class);
  }

  @Test
  void testGetNextTslSeqNr() {
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();

    final int tslSeqNr = 420000;
    tslSequenceNr.setLastOfferedTslSeqNr(tslSeqNr);

    assertThat(tslSequenceNr.getNextTslSeqNr())
        .isEqualTo(tslSequenceNr.getLastOfferedTslSeqNr() + 1);

    tslSequenceNr.setLastOfferedTslSeqNr(0);
    tslSequenceNr.saveCurrentTestObjectTslSeqNr(1000);
    assertThat(tslSequenceNr.getNextTslSeqNr()).isEqualTo(1001);
  }

  @Test
  void testToString() {
    final TslSequenceNr tslSequenceNr = TslSequenceNr.getInstance();
    assertDoesNotThrow(tslSequenceNr::toString);
  }
}
