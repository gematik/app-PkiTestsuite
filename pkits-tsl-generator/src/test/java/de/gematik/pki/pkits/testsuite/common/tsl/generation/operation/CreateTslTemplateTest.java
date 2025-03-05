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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TSL_CERT_TSL_CA28_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TSL_OCSP_SIGNER_10_CERT_SHA256;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TU_ECC_ONLY_TSL;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.ARVATO_TU_TSL;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate.deleteInitialTspServices;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
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

  private TslContainer tslRSAContainer = null;
  private TslContainer tslECCContainer = null;

  @BeforeEach
  void setUp() {
    tslRSAContainer = new TslContainer(TslReader.getTslUnsigned(ARVATO_TU_TSL));
    tslECCContainer = new TslContainer(TslReader.getTslUnsigned(ARVATO_TU_ECC_ONLY_TSL));
  }

  @Test
  void verifyRSADeleteInitialTspServices() {

    final int oldTslBytes = tslRSAContainer.getAsTslUnsignedBytes().length;
    final int newTslBytes =
        deleteInitialTspServices(tslRSAContainer).getAsTslUnsignedBytes().length;
    assertThat(newTslBytes).isLessThan(oldTslBytes);
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
  void verifyRSAToRemoveCertExists(final String certhash) {
    assertThat(new DeleteTspServiceForCertShaTslOperation(certhash).count(tslRSAContainer))
        .isEqualTo(1);
  }

  @ParameterizedTest
  @ValueSource(strings = {ARVATO_TSL_CERT_TSL_CA28_SHA256, ARVATO_TSL_OCSP_SIGNER_10_CERT_SHA256})
  void verifyECCToRemoveCertExists(final String certhash) {
    assertThat(new DeleteTspServiceForCertShaTslOperation(certhash).count(tslECCContainer))
        .isEqualTo(1);
  }

  @Test
  void testGetRSATspServicesForCertsException() {
    final List<TSPServiceType> tspServices =
        CreateTslTemplate.defaultTsl(false)
            .getTrustServiceProviderList()
            .getTrustServiceProvider()
            .get(0)
            .getTSPServices()
            .getTSPService();

    assertThatThrownBy(() -> CreateTslTemplate.getTspServicesForCerts(tspServices))
        .isInstanceOf(TslGenerationException.class)
        .cause()
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("length of certs is 0");
  }

  @Test
  void testGetECCTspServicesForCertsException() {
    final List<TSPServiceType> tspServices =
        CreateTslTemplate.defaultTsl(true)
            .getTrustServiceProviderList()
            .getTrustServiceProvider()
            .get(0)
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
  void testCheckRsaTspServicesForDuplication() {
    final List<TSPServiceType> allTspServiceTypes =
        CreateTslTemplate.defaultTsl(false)
            .getTrustServiceProviderList()
            .getTrustServiceProvider()
            .stream()
            .flatMap(provider -> provider.getTSPServices().getTSPService().stream())
            .toList();

    assertThat(TslGenerationTestUtils.duplicatedTspServicesTypesFound(allTspServiceTypes))
        .isFalse();
  }

  @Test
  void testGetEccTspServicesForDuplication() {
    final List<TSPServiceType> allTspServices =
        CreateTslTemplate.defaultTsl(true)
            .getTrustServiceProviderList()
            .getTrustServiceProvider()
            .stream()
            .flatMap(provider -> provider.getTSPServices().getTSPService().stream())
            .toList();

    assertThat(TslGenerationTestUtils.duplicatedTspServicesTypesFound(allTspServices)).isFalse();
  }

  @Test
  void verifyDefaultRSATsl() {
    final TrustStatusListType tsl = CreateTslTemplate.defaultTsl(false);
    assertThat(tsl.getSignature()).isNull();

    final List<TSPType> tspList =
        tsl.getTrustServiceProviderList().getTrustServiceProvider().stream()
            .filter(
                tsp ->
                    tsp.getTSPInformation()
                        .getTSPName()
                        .getName()
                        .get(0)
                        .getValue()
                        .equals(PkitsConstants.GEMATIK_TEST_TSP))
            .toList();

    assertThat(tspList).hasSize(1);

    final TSPType tsp = tspList.get(0);

    assertThat(tsp.getTSPServices().getTSPService()).hasSize(10);

    final List<TSPServiceType> pkcTspServices =
        tsp.getTSPServices().getTSPService().stream()
            .filter(
                tspService ->
                    tspService
                        .getServiceInformation()
                        .getServiceTypeIdentifier()
                        .equals(TslConstants.STI_PKC))
            .toList();
    assertThat(pkcTspServices).hasSize(8);

    final List<TSPServiceType> ocspTspServices =
        tsp.getTSPServices().getTSPService().stream()
            .filter(
                tspService ->
                    tspService
                        .getServiceInformation()
                        .getServiceTypeIdentifier()
                        .equals(TslConstants.STI_OCSP))
            .toList();
    assertThat(ocspTspServices).hasSize(2);
  }

  @Test
  void verifyDefaultECCTsl() {
    final TrustStatusListType tsl = CreateTslTemplate.defaultTsl(true);
    assertThat(tsl.getSignature()).isNull();

    final List<TSPType> tspList =
        tsl.getTrustServiceProviderList().getTrustServiceProvider().stream()
            .filter(
                tsp ->
                    tsp.getTSPInformation()
                        .getTSPName()
                        .getName()
                        .get(0)
                        .getValue()
                        .equals(PkitsConstants.GEMATIK_TEST_TSP))
            .toList();

    assertThat(tspList).hasSize(1);

    final TSPType tsp = tspList.get(0);

    assertThat(tsp.getTSPServices().getTSPService()).hasSize(6);

    final List<TSPServiceType> pkcTspServices =
        tsp.getTSPServices().getTSPService().stream()
            .filter(
                tspService ->
                    tspService
                        .getServiceInformation()
                        .getServiceTypeIdentifier()
                        .equals(TslConstants.STI_PKC))
            .toList();
    assertThat(pkcTspServices).hasSize(5);

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
  void verifyRSATsls() {
    final ZonedDateTime now = GemLibPkiUtils.now();
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaRevokedLaterTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaUnspecifiedStiTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectAlternativeCaBrokenTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectAlternativeCaWrongSrvInfoExtTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaRevokedTsl(false));
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(false));
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(now, false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeNotYetValidTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeExpiredTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeTwoEntriesTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeStartingTimeFutureTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeBrokenTsl(false));
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(now, false));
    assertDoesNotThrow(
        () -> CreateTslTemplate.invalidAlternativeTrustAnchorExpiredAlternativeCaTsl(false));
    assertDoesNotThrow(
        () -> CreateTslTemplate.invalidAlternativeTrustAnchorNotYetValidAlternativeCaTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl(false));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl(false));
  }

  @Test
  void verifyECCTsls() {
    final ZonedDateTime now = GemLibPkiUtils.now();
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaRevokedLaterTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaUnspecifiedStiTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectAlternativeCaBrokenTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectAlternativeCaWrongSrvInfoExtTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeCaRevokedTsl(true));
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(true));
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeFromDefaultToAlternativeFirstTsl(now, true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchorAlternativeCaTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchorTrustAnchorChangeTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeNotYetValidTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeExpiredTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeTwoEntriesTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeStartingTimeFutureTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.defectTrustAnchorChangeBrokenTsl(true));
    assertDoesNotThrow(
        () -> CreateTslTemplate.trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(now, true));
    assertDoesNotThrow(
        () -> CreateTslTemplate.invalidAlternativeTrustAnchorExpiredAlternativeCaTsl(true));
    assertDoesNotThrow(
        () -> CreateTslTemplate.invalidAlternativeTrustAnchorNotYetValidAlternativeCaTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchor2AlternativeCaTsl(true));
    assertDoesNotThrow(() -> CreateTslTemplate.alternativeTrustAnchor2TrustAnchorChangeTsl(true));
  }
}
