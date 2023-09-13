/*
 * Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.tsl.provider.data;

import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TslRequestHistoryTest {
  public static TslRequestHistoryEntryDto getEntry(final int tslSeqNr) {
    return new TslRequestHistoryEntryDto(tslSeqNr, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
  }

  @Test
  void testAdd1() {
    final TslRequestHistory tslRequestHistory = new TslRequestHistory();
    assertThat(tslRequestHistory.size()).isZero();
    tslRequestHistory.add(getEntry(42));
    assertThat(tslRequestHistory.size()).isEqualTo(1);
  }

  @Test
  void testAdd2() {
    final TslRequestHistory tslRequestHistory = new TslRequestHistory();
    assertThat(tslRequestHistory.size()).isZero();
    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
    assertThat(tslRequestHistory.size()).isEqualTo(1);
  }

  @Test
  void testGetExcerpt() {
    final TslRequestHistory tslRequestHistory = new TslRequestHistory();

    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");

    final List<TslRequestHistoryEntryDto> excerpt = tslRequestHistory.getExcerpt(42);

    assertThat(excerpt).hasSize(2);
  }

  @Test
  void testDeleteEntries() {
    final TslRequestHistory tslRequestHistory = new TslRequestHistory();

    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
    tslRequestHistory.add(100, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");

    assertThat(tslRequestHistory.size()).isEqualTo(3);
    tslRequestHistory.deleteEntries(42);

    assertThat(tslRequestHistory.size()).isEqualTo(1);

    tslRequestHistory.deleteEntries(42);
    assertThat(tslRequestHistory.size()).isEqualTo(1);
    tslRequestHistory.deleteEntries(100);
    assertThat(tslRequestHistory.size()).isZero();
  }

  @Test
  void testDeleteAll() {
    final TslRequestHistory tslRequestHistory = new TslRequestHistory();

    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
    tslRequestHistory.add(100, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");
    tslRequestHistory.add(42, TSL_XML_PRIMARY_ENDPOINT, true, "HTTP/1.1");

    assertThat(tslRequestHistory.size()).isEqualTo(3);
    tslRequestHistory.deleteAll();

    assertThat(tslRequestHistory.size()).isZero();
  }
}
