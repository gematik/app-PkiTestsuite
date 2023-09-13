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

package de.gematik.pki.pkits.ocsp.responder;

import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfig;
import java.math.BigInteger;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Data
public class OcspResponseConfigHolder {

  private OcspResponderConfig ocspResponderConfig;

  public boolean isConfigured() {
    return ocspResponderConfig != null;
  }

  public boolean isCertSerialNrConfigured(final BigInteger certSerialNr) {
    log.debug("Requested  certSerialNr: {}", certSerialNr);
    log.debug("Configured certSerialNr: {}", ocspResponderConfig.getEeCert().getSerialNumber());
    return ocspResponderConfig.getEeCert().getSerialNumber().equals(certSerialNr);
  }
}
