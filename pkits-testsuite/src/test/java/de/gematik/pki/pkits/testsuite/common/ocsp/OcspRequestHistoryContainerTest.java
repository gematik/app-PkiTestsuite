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

package de.gematik.pki.pkits.testsuite.common.ocsp;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.ocsp.responder.api.OcspResponderManager;
import de.gematik.pki.pkits.ocsp.responder.data.OcspRequestHistoryEntryDto;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class OcspRequestHistoryContainerTest {

  @Test
  void testOcspRequestHistoryHasEntryForCert() throws Exception {
    final OcspRequestHistoryContainer ocspRequestHistoryContainer =
        new OcspRequestHistoryContainer();

    final OcspRequestHistoryEntryDto historyEntry =
        new OcspRequestHistoryEntryDto(1, BigInteger.TEN, "timeStamp", new byte[] {});

    try (final MockedStatic<OcspResponderManager> ocspResponderManagerMockedStatic =
        Mockito.mockStatic(OcspResponderManager.class, Mockito.CALLS_REAL_METHODS)) {

      ocspResponderManagerMockedStatic
          .when(() -> OcspResponderManager.getOcspHistoryPart("dummyUri", 1, BigInteger.TEN))
          .thenReturn(List.of(historyEntry));

      assertThat(ocspRequestHistoryContainer.getHistoryEntries()).isEmpty();
      boolean hasEntries =
          ocspRequestHistoryContainer
              .ocspRequestHistoryHasEntryForCert("dummyUri", 1, BigInteger.TEN)
              .call();
      assertThat(hasEntries).isTrue();
      assertThat(ocspRequestHistoryContainer.getHistoryEntries()).hasSize(1);

      ocspRequestHistoryContainer.reset();
      assertThat(ocspRequestHistoryContainer.getHistoryEntries()).isEmpty();

      ocspResponderManagerMockedStatic
          .when(() -> OcspResponderManager.getOcspHistoryPart("dummyUri", 1, BigInteger.TEN))
          .thenReturn(List.of(historyEntry, historyEntry));

      hasEntries =
          ocspRequestHistoryContainer
              .ocspRequestHistoryHasEntryForCert("dummyUri", 1, BigInteger.TEN)
              .call();
      assertThat(hasEntries).isTrue();
      assertThat(ocspRequestHistoryContainer.getHistoryEntries()).hasSize(2);

      ocspResponderManagerMockedStatic
          .when(
              () ->
                  OcspResponderManager.getOcspHistoryPart(
                      Mockito.any(), Mockito.any(), Mockito.any()))
          .thenReturn(List.of());

      hasEntries =
          ocspRequestHistoryContainer
              .ocspRequestHistoryHasEntryForCert("dummyUri", 1, BigInteger.TEN)
              .call();
      assertThat(hasEntries).isFalse();
      assertThat(ocspRequestHistoryContainer.getHistoryEntries()).isEmpty();
    }
  }
}
