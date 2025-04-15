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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.charset.StandardCharsets;
import lombok.AllArgsConstructor;
import org.bouncycastle.util.encoders.Hex;

@AllArgsConstructor
public class DeleteTspServiceForCertShaTslOperation implements TslOperation {
  private final String referenceSha256;

  private boolean sameSha256(final TSPServiceType tspService) {
    final byte[] certBytes =
        tspService
            .getServiceInformation()
            .getServiceDigitalIdentity()
            .getDigitalId()
            .get(0)
            .getX509Certificate();

    if (certBytes == null) {
      return false;
    }

    final byte[] certSha256 = GemLibPkiUtils.calculateSha256(certBytes);
    final String certSha256Str = new String(Hex.encode(certSha256), StandardCharsets.UTF_8);

    return referenceSha256.equals(certSha256Str);
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();

    for (final TSPType tsp : tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider()) {
      tsp.getTSPServices().getTSPService().removeIf(this::sameSha256);
    }

    return new TslContainer(tslUnsigned);
  }

  public long count(final TslContainer tslContainer) {
    return tslContainer
        .getAsTslUnsigned()
        .getTrustServiceProviderList()
        .getTrustServiceProvider()
        .stream()
        .flatMap(tsp -> tsp.getTSPServices().getTSPService().stream())
        .filter(this::sameSha256)
        .count();
  }
}
