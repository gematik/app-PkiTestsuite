/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.config;

import java.nio.file.Path;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OcspSettings {

  @ParameterDescription(
      withDefault = true,
      description =
          "Absolute or relative path to key store files in p12 format to sign OCSP requests."
              + " with.")
  Path keystorePathOcsp = Path.of("./testDataTemplates/certificates/ecc/ocspKeystore");

  @ParameterDescription(
      withDefault = true,
      description = "Password used for the OCSP signer key store.")
  String signerPassword = "00"; // NOSONAR

  @ParameterDescription(
      withDefault = true,
      description =
          "Amount of milliseconds to add/subtract from OCSP timeout during the test to get a"
              + " result inside/outside the timeout.")
  int timeoutDeltaMilliseconds = 1500;

  @ParameterDescription(
      withDefault = true,
      description = "Amount of seconds to add to the OCSP grace period as a buffer.")
  int gracePeriodExtraDelay = 5;
}
