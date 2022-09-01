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

package de.gematik.pki.pkits.ocsp.responder.data;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.time.ZonedDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

class OcspRequestHistoryTest {

  /** Store one element, check size, TSL seqNr does not matter */
  @Test
  void add() {
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(
            new BigInteger("10000"), ZonedDateTime.now().toString(), 42));
    assertThat(ocspRequestHistory.size()).isEqualTo(1);
  }

  /**
   * Store some elements with different certSerialNr, get excerpt and check certSerialNr, TSL seqNr
   * does not matter
   */
  @Test
  void getExcerptExpectOne() {
    final BigInteger certSerialNr = new BigInteger("20000");
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10000"), ZonedDateTime.now().toString(), 3));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(certSerialNr, ZonedDateTime.now().toString(), 9));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("30000"), ZonedDateTime.now().toString(), 7));

    final List<OcspRequestHistoryEntryDto> excerpt = ocspRequestHistory.getExcerpt(certSerialNr);
    assertThat(excerpt).hasSize(1);
    assertThat(excerpt.get(0).getCertSerialNr()).isEqualTo(certSerialNr);
  }

  /**
   * Store some elements with same and different certSerialNr, get excerpt and check amount and
   * certSerialNr,TSL seqNr does not matter
   */
  @Test
  void getExcerptExpectSeveral() {
    final BigInteger certSerialNr = new BigInteger("4711");
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(
            new BigInteger("10000"), ZonedDateTime.now().toString(), 100));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(certSerialNr, ZonedDateTime.now().toString(), 66));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(certSerialNr, ZonedDateTime.now().toString(), 66));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(
            new BigInteger("30000"), ZonedDateTime.now().toString(), 24));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(certSerialNr, ZonedDateTime.now().toString(), 6));

    final List<OcspRequestHistoryEntryDto> excerpt = ocspRequestHistory.getExcerpt(certSerialNr);
    assertThat(excerpt).hasSize(3);
    assertThat(excerpt.get(0).getCertSerialNr()).isEqualTo(certSerialNr);
  }

  /**
   * Store some elements with different certSerialNr, delete one and check size, TSL seqNr does not
   * matter
   */
  @Test
  void deleteUniqueEntry() {
    final int elementsPut = 100;
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    for (int i = 0; i < elementsPut; i++) {
      ocspRequestHistory.add(
          new OcspRequestHistoryEntryDto(
              new BigInteger("10" + i), ZonedDateTime.now().toString(), 45));
    }
    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut);
    ocspRequestHistory.deleteEntries(new BigInteger("10" + 5));
    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut - 1);
  }

  /**
   * Store some elements, some of them have equal certSerialNr, delete them and check size, TSL
   * seqNr does not matter
   */
  @Test
  void deleteSameEntries() {
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10"), ZonedDateTime.now().toString(), 87));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("15"), ZonedDateTime.now().toString(), 44));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10"), ZonedDateTime.now().toString(), 102));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10"), ZonedDateTime.now().toString(), 1));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("42"), ZonedDateTime.now().toString(), 17));

    ocspRequestHistory.deleteEntries(new BigInteger("10"));
    assertThat(ocspRequestHistory.size()).isEqualTo(2);
  }

  /** Store some elements, delete all and check size, TSL seqNr does not matter */
  @Test
  void deleteAll() {
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();

    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10"), ZonedDateTime.now().toString(), 4));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("15"), ZonedDateTime.now().toString(), 4));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10"), ZonedDateTime.now().toString(), 14));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("10"), ZonedDateTime.now().toString(), 4));
    ocspRequestHistory.add(
        new OcspRequestHistoryEntryDto(new BigInteger("42"), ZonedDateTime.now().toString(), 36));

    ocspRequestHistory.deleteAll();
    assertThat(ocspRequestHistory.size()).isZero();
  }

  /** Store some elements and check size, TSL seqNr does not matter */
  @Test
  void size() {
    final int elementsPut = 42;
    final OcspRequestHistory ocspRequestHistory = new OcspRequestHistory();
    assertThat(ocspRequestHistory.size()).isZero();
    for (int i = 0; i < elementsPut; i++) {
      ocspRequestHistory.add(
          new OcspRequestHistoryEntryDto(
              new BigInteger("10000" + i), ZonedDateTime.now().toString(), 18));
    }
    assertThat(ocspRequestHistory.size()).isEqualTo(elementsPut);
  }
}
