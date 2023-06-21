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

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ClientConfig {

  @ParameterDescription(
      description =
          "Absolute or relative path to valid key store end-entity files in p12 format for the"
              + " tests.")
  private String keystorePathValidCerts;

  @ParameterDescription(
      description =
          "Absolute or relative path to valid key store end-entity files of an alternative CA in"
              + " p12 format for the tests.")
  private String keystorePathAlternativeCerts;

  @ParameterDescription(
      description =
          "Absolute or relative path to invalid key store end-entity files in p12 format for the"
              + " tests.")
  private String keystorePathInvalidCerts;

  @ParameterDescription(
      withDefault = true,
      description = "Password used for all p12 key store files of the test certificates.")
  private String keystorePassword = "00"; // NOSONAR
}
