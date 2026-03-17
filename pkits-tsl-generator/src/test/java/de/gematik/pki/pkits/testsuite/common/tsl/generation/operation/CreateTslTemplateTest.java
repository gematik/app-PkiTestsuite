/*
 * Copyright (Change Date see Readme), gematik GmbH
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

import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TSL_CERT_TSL_CA28_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TSL_OCSP_SIGNER_10_CERT_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TU_ECC_ONLY_TSL;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.deleteInitialTspServices;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.tsl.TslConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TslReader;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.exeptions.TslGenerationException;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.time.ZonedDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CreateTslTemplateTest {

  private TslContainer tslECCContainer = null;

  @BeforeEach
  void setUp() {
    tslECCContainer = new TslContainer(TslReader.getTslUnsigned(ARVATO_TU_ECC_ONLY_TSL));
  }

  @Test
  void verifyECCDeleteInitialTspServices() {

    final int oldTslBytes = tslECCContainer.getAsTslUnsignedBytes().length;
    final int newTslBytes =
        deleteInitialTspServices(tslECCContainer).getAsTslUnsignedBytes().length;
    assertThat(newTslBytes).isLessThan(oldTslBytes);
  }

  @ParameterizedTest
  @ValueSource(strings = {ARVATO_TSL_CERT_TSL_CA28_SHA256, ARVATO_TSL_OCSP_SIGNER_10_CERT_SHA256})
  void verifyECCToRemoveCertExists(final String certhash) {
    assertThat(new DeleteTspServiceForCertShaTslOperation(certhash).count(tslECCContainer))
        .isEqualTo(1);
  }

  @Test
  void testGetECCTspServicesForCertsException() {
    final List<TSPServiceType> tspServices =
        CreateTslTemplate.defaultTsl()
            .getTrustServiceProviderList()
            .getTrustServiceProvider()
            .getFirst()
            .getTSPServices()
            .getTSPService();

    assertThatThrownBy(() -> CreateTslTemplate.getTspServicesForCerts(tspServices))
        .isInstanceOf(TslGenerationException.class)
        .cause()
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("length of certs is 0");
  }

  @Test
  void testCheckDiscoverTspServicesForDuplication() {
    final String TSL_WITH_DUPLICATED_TSP_SERVICE = "tsl_duplicated_tsp_GEM.TSL-CA51_TEST-ONLY.xml";
    assertThat(
            TslGenerationTestUtils.duplicatedTspServicesFound(
                TslGenerationTestUtils.getTspServices(TSL_WITH_DUPLICATED_TSP_SERVICE)))
        .isTrue();
  }

  @Test
  void testGetEccTspServicesForDuplication() {
    final List<TSPServiceType> allTspServices =
        CreateTslTemplate.defaultTsl()
            .getTrustServiceProviderList()
            .getTrustServiceProvider()
            .stream()
            .flatMap(provider -> provider.getTSPServices().getTSPService().stream())
            .toList();

    assertThat(TslGenerationTestUtils.duplicatedTspServicesTypesFound(allTspServices)).isFalse();
  }

  @Test
  void verifyDefaultECCTsl() {
    final TrustStatusListType tsl = CreateTslTemplate.defaultTsl();
    assertThat(tsl.getSignature()).isNull();

    final List<TSPType> tspList =
        tsl.getTrustServiceProviderList().getTrustServiceProvider().stream()
            .filter(
                tsp ->
                    tsp.getTSPInformation()
                        .getTSPName()
                        .getName()
                        .getFirst()
                        .getValue()
                        .equals(PkitsConstants.GEMATIK_TEST_TSP))
            .toList();

    assertThat(tspList).hasSize(1);

    final TSPType tsp = tspList.getFirst();

    assertThat(tsp.getTSPServices().getTSPService()).hasSize(7);

    final List<TSPServiceType> pkcTspServices =
        tsp.getTSPServices().getTSPService().stream()
            .filter(
                tspService ->
                    tspService
                        .getServiceInformation()
                        .getServiceTypeIdentifier()
                        .equals(TslConstants.STI_PKC))
            .toList();
    assertThat(pkcTspServices).hasSize(6);

    final List<TSPServiceType> ocspTspServices =
        tsp.getTSPServices().getTSPService().stream()
            .filter(
                tspService ->
                    tspService
                        .getServiceInformation()
                        .getServiceTypeIdentifier()
                        .equals(TslConstants.STI_OCSP))
            .toList();
    assertThat(ocspTspServices).hasSize(1);
  }

  @Test
  void verifyECCTsls() {
    final ZonedDateTime now = GemLibPkiUtils.now();
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaRevokedLaterTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaUnspecifiedStiTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectAlternativeCaBrokenTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectAlternativeCaWrongSrvInfoExtTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaRevokedTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl());
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(now));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeNotYetValidTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeExpiredTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeTwoEntriesTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeStartingTimeFutureTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeBrokenTsl());
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(now));
    assertDoesNotThrow(
        () -> CreateTslTemplate.invalidAlternativeTrustAnchorExpiredAlternativeCaTsl());
    assertDoesNotThrow(
        () -> CreateTslTemplate.invalidAlternativeTrustAnchorNotYetValidAlternativeCaTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl());
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl());
  }
}
