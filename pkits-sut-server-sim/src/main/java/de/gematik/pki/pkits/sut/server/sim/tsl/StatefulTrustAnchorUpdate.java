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

package de.gematik.pki.pkits.sut.server.sim.tsl;

import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier.TrustAnchorUpdate;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
class StatefulTrustAnchorUpdate {

  private TrustAnchorUpdateStatus status = TrustAnchorUpdateStatus.NONE;
  private TrustAnchorUpdate trustAnchorUpdate = null;
  private TspService tspServiceFutureTrustAnchor = null;

  private void makeSaved(
      final TrustAnchorUpdate trustAnchorUpdate, final TspService tspServiceWithTslSignerCa) {
    this.trustAnchorUpdate = trustAnchorUpdate;
    tspServiceFutureTrustAnchor = tspServiceWithTslSignerCa;
    status = TrustAnchorUpdateStatus.SAVED;

    log.info(
        "saved new trustAnchorUpdate: cert serialNumber {}, statusStartingTime {}",
        trustAnchorUpdate.getFutureTrustAnchor().getSerialNumber(),
        trustAnchorUpdate.getStatusStartingTime());
    log.info("TrustAnchorUpdateStatus.{} - changed right now", status);
  }

  TspService getFutureTspServiceTrustAnchorOrCurrent(final TspService currentTspService) {

    if ((status == TrustAnchorUpdateStatus.SAVED) && trustAnchorUpdate.isToActivateNow()) {
      log.info(
          "activated trustAnchorUpdate: cert serialNumber {}, statusStartingTime {}",
          trustAnchorUpdate.getFutureTrustAnchor().getSerialNumber(),
          trustAnchorUpdate.getStatusStartingTime());

      trustAnchorUpdate = null;
      status = TrustAnchorUpdateStatus.ACTIVATED;
      log.info("trustAnchorUpdateStatus.{} - changed right now", status);

      return tspServiceFutureTrustAnchor;
    }
    log.info("trustAnchorUpdateStatus.{} - not changed", status);
    return currentTspService;
  }

  void reset() {
    if (status == TrustAnchorUpdateStatus.ACTIVATED) {
      trustAnchorUpdate = null;
      tspServiceFutureTrustAnchor = null;
      status = TrustAnchorUpdateStatus.NONE;
      log.info("TrustAnchorUpdateStatus.NONE changed right now");
    }
  }

  void updateTrustAnchorIfNecessary(
      final Tsl rxTsl, final Optional<TrustAnchorUpdate> newTrustAnchorUpdateOpt) {

    if (newTrustAnchorUpdateOpt.isPresent()) {
      final TSPServiceType tspServiceType =
          getTspServiceTSLServiceCertChange(rxTsl.trustStatusListType);
      final TspService tspServiceNewTrustAnchor = new TspService(tspServiceType);
      makeSaved(newTrustAnchorUpdateOpt.get(), tspServiceNewTrustAnchor);
    }
  }

  private static List<TSPServiceType> getChangeCertTspServices(final TrustStatusListType tsl) {
    return new TslInformationProvider(tsl)
        .getFilteredTspServices(List.of(TslConstants.STI_SRV_CERT_CHANGE)).stream()
            .map(TspService::getTspServiceType)
            .toList();
  }

  private static TSPServiceType getTspServiceTSLServiceCertChange(final TrustStatusListType tsl) {
    return getChangeCertTspServices(tsl).get(0);
  }
}
