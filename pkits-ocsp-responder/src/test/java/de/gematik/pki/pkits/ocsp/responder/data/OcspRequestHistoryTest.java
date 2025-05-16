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

package de.gematik.pki.pkits.ocsp.responder.data;

import static de.gematik.pki.pkits.ocsp.responder.controllers.OcspResponderTestUtils.getEntry;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import java.math.BigInteger;
import java.util.List;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class OcspRequestHistoryTest {

  /** Store one element, check size, tslSeqNr does not matter */
  @Test
  void add() {
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    ocspRequestHistory.add(getEntry(42, "10000"));
    assertThat(ocspRequestHistory.size()).isEqualTo(1);
  }

  /** Store one element, check size, tslSeqNr does not matter */
  @Test
  void add2() {
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    ocspRequestHistory.add(getEntry(42, "10000"));
    assertThat(ocspRequestHistory.size()).isEqualTo(1);
  }

  /**
   * Store some elements with different certSerialNr, get excerpt and check certSerialNr, tslSeqNr
   * does not matter
   */
  @Test
  void getExcerptExpectOne() {

    final String certSerialNrStr = "20000";
    final BigInteger certSerialNr = new BigInteger(certSerialNrStr);
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    assertThat(ocspRequestHistory.size()).isZero();

    ocspRequestHistory.add(getEntry(3, "10000"));

    ocspRequestHistory.add(getEntry(7, certSerialNrStr));

    ocspRequestHistory.add(getEntry(7, "30000"));
    ocspRequestHistory.add(getEntry(8, certSerialNrStr));

    final List<OcspRequestHistoryEntryDto> excerpt = ocspRequestHistory.getExcerpt(7, certSerialNr);
    assertThat(excerpt).hasSize(1);
    assertThat(excerpt.get(0).getCertSerialNr()).isEqualTo(certSerialNr);
    assertThat(excerpt.get(0).getTslSeqNr()).isEqualTo(7);
  }

  /**
   * Store some elements with same and different certSerialNr, get excerpt and check amount and
   * certSerialNr, tslSeqNr does not matter
   */
  @Test
  void getExcerptExpectSeveral() {
    final String certSerialNrStr = "4711";
    final BigInteger certSerialNr = new BigInteger(certSerialNrStr);
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    assertThat(ocspRequestHistory.size()).isZero();

    ocspRequestHistory.add(getEntry(100, "10000"));

    ocspRequestHistory.add(getEntry(55, certSerialNrStr));
    ocspRequestHistory.add(getEntry(55, certSerialNrStr));

    ocspRequestHistory.add(getEntry(77, "30000"));
    ocspRequestHistory.add(getEntry(77, certSerialNrStr));

    ocspRequestHistory.add(getEntry(55, "30000"));

    {
      final List<OcspRequestHistoryEntryDto> excerpt =
          ocspRequestHistory.getExcerpt(55, certSerialNr);
      assertThat(excerpt).hasSize(2);
      assertThat(excerpt.get(0).getCertSerialNr()).isEqualTo(certSerialNr);

      assertThat(excerpt.get(0).getTslSeqNr()).isEqualTo(55);
      assertThat(excerpt.get(1).getTslSeqNr()).isEqualTo(55);
    }

    {
      final List<OcspRequestHistoryEntryDto> excerpt =
          ocspRequestHistory.getExcerpt(OcspResponderManager.IGNORE_SEQUENCE_NUMBER, certSerialNr);
      assertThat(excerpt).hasSize(3);
      assertThat(excerpt.get(0).getCertSerialNr()).isEqualTo(certSerialNr);

      assertThat(excerpt.get(0).getTslSeqNr()).isEqualTo(55);
      assertThat(excerpt.get(1).getTslSeqNr()).isEqualTo(55);
      assertThat(excerpt.get(2).getTslSeqNr()).isEqualTo(77);
    }

    {
      final List<OcspRequestHistoryEntryDto> excerpt =
          ocspRequestHistory.getExcerpt(55, OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);
      assertThat(excerpt).hasSize(3);
      assertThat(excerpt.get(0).getTslSeqNr()).isEqualTo(55);

      assertThat(excerpt.get(0).getCertSerialNr()).isEqualTo(certSerialNr);
      assertThat(excerpt.get(1).getCertSerialNr()).isEqualTo(certSerialNr);
      assertThat(excerpt.get(2).getCertSerialNr()).isEqualTo(new BigInteger("30000"));
    }
  }

  /**
   * Store some elements with different certSerialNr, delete one and check size, tslSeqNr does not
   * matter
   */
  @Test
  void deleteUniqueEntryForCertSerialNr() {
    final int elementsPut = 100;
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    assertThat(ocspRequestHistory.size()).isZero();

    for (int i = 0; i < elementsPut; i++) {
      ocspRequestHistory.add(getEntry(45, "10" + i));
    }

    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut);

    ocspRequestHistory.deleteEntries(
        OcspResponderManager.IGNORE_SEQUENCE_NUMBER, new BigInteger("10" + 5));

    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut - 1);
  }

  /**
   * Store some elements with different tslSeqNr, delete one and check size, tslSeqNr does not
   * matter
   */
  @Test
  void deleteUniqueEntryForTslSeqNr() {
    final int elementsPut = 100;
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    assertThat(ocspRequestHistory.size()).isZero();

    for (int i = 0; i < elementsPut; i++) {
      ocspRequestHistory.add(getEntry(10 + i, "45"));
    }

    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut);

    ocspRequestHistory.deleteEntries(15, OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);

    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut - 1);
  }

  /**
   * Store some elements, some of them have equal certSerialNr, delete them and check size, tslSeqNr
   * does not matter
   */
  @Test
  void deleteSameEntries() {

    final Supplier<OcspRequestHistory> historySupplier =
        () -> {
          final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

          ocspRequestHistory.add(getEntry(11, "10"));
          ocspRequestHistory.add(getEntry(55, "15"));
          ocspRequestHistory.add(getEntry(11, "10"));
          ocspRequestHistory.add(getEntry(55, "10"));
          ocspRequestHistory.add(getEntry(44, "42"));
          ocspRequestHistory.add(getEntry(11, "42"));
          return ocspRequestHistory;
        };

    final int origHistorySize = historySupplier.get().size();
    OcspRequestHistory ocspRequestHistory;

    ocspRequestHistory = historySupplier.get();
    ocspRequestHistory.deleteEntries(11, new BigInteger("10"));
    assertThat(ocspRequestHistory.size()).isEqualTo(origHistorySize - 2);

    ocspRequestHistory.deleteEntries(
        OcspResponderManager.IGNORE_SEQUENCE_NUMBER, new BigInteger("10"));
    assertThat(ocspRequestHistory.size()).isEqualTo(origHistorySize - 3);

    ocspRequestHistory = historySupplier.get();
    ocspRequestHistory.deleteEntries(null, new BigInteger("10"));
    assertThat(ocspRequestHistory.size()).isEqualTo(origHistorySize - 3);

    ocspRequestHistory = historySupplier.get();
    ocspRequestHistory.deleteEntries(55, OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);
    assertThat(ocspRequestHistory.size()).isEqualTo(origHistorySize - 2);

    ocspRequestHistory = historySupplier.get();
    ocspRequestHistory.deleteEntries(11, null);
    assertThat(ocspRequestHistory.size()).isEqualTo(origHistorySize - 3);

    ocspRequestHistory = historySupplier.get();
    ocspRequestHistory.deleteEntries(
        OcspResponderManager.IGNORE_SEQUENCE_NUMBER,
        OcspResponderManager.IGNORE_CERT_SERIAL_NUMBER);
    assertThat(ocspRequestHistory.size()).isZero();
  }

  /** Store some elements, delete all and check size, tslSeqNr does not matter */
  @Test
  void deleteAll() {
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    ocspRequestHistory.add(getEntry(4, "10"));
    ocspRequestHistory.add(getEntry(4, "15"));
    ocspRequestHistory.add(getEntry(14, "10"));
    ocspRequestHistory.add(getEntry(4, "10"));
    ocspRequestHistory.add(getEntry(36, "42"));

    ocspRequestHistory.deleteAll();
    assertThat(ocspRequestHistory.size()).isZero();
  }

  /** Store some elements and check size, tslSeqNr does not matter */
  @Test
  void size() {
    final int elementsPut = 42;
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    for (int i = 0; i < elementsPut; i++) {
      ocspRequestHistory.add(getEntry(18, "10000" + i));
    }
    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut);
  }
}
