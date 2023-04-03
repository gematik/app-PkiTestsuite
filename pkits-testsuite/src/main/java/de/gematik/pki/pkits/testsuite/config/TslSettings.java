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

package de.gematik.pki.pkits.testsuite.config;

import java.nio.file.Path;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TslSettings {

  @ParameterDescription(
      withDefault = true,
      description = "Import a new TSL during initial state in each use case.")
  boolean initialStateTslImport = true;

  @ParameterDescription(
      withDefault = true,
      description = "Default template to generate TSL during tests from.")
  Path defaultTemplate = Path.of("./testDataTemplates/tsl/TSL_default.xml");

  @ParameterDescription(
      withDefault = true,
      description = "Alternative template to generate a TSL with additional CAs during tests.")
  Path alternativeTemplate = Path.of("./testDataTemplates/tsl/TSL_altCA.xml");

  @ParameterDescription(
      withDefault = true,
      description =
          "Alternative template to generate a TSL with an additional broken CA during tests.")
  Path defectAlternativeCaBrokenTemplate =
      Path.of("./testDataTemplates/tsl/TSL_defect_altCA_broken.xml");

  @ParameterDescription(
      withDefault = true,
      description =
          "Alternative template to generate a TSL with an additional unspecified CA during tests.")
  Path defectAlternativeCaUnspecifiedTemplate =
      Path.of("./testDataTemplates/tsl/TSL_defect_unspecified-CA_altCA.xml");

  @ParameterDescription(
      withDefault = true,
      description =
          "Alternative template to generate a TSL with an additional wrong (service info extension)"
              + " CA during tests.")
  Path defectAlternativeCaWrongSrvInfoExtTemplate =
      Path.of("./testDataTemplates/tsl/TSL_defect_altCA_wrong-srvInfoExt.xml");

  @ParameterDescription(
      withDefault = true,
      description =
          "Alternative template to generate a TSL with an unspecified ServiceTypeIdentifier in TSP"
              + " service during tests.")
  Path alternativeCaUnspecifiedStiTemplate =
      Path.of("./testDataTemplates/tsl/TSL_altCA_unspecifiedSTI.xml");

  @ParameterDescription(
      withDefault = true,
      description =
          "Alternative template to generate a TSL with additional revoked CAs during tests.")
  Path alternativeRevokedTemplate = Path.of("./testDataTemplates/tsl/TSL_altCA_revoked.xml");

  @ParameterDescription(
      withDefault = true,
      description =
          "Alternative template to generate a TSL with additional CAs without line breaks during"
              + " tests.")
  Path alternativeNoLineBreakTemplate =
      Path.of("./testDataTemplates/tsl/TSL_altCA_noLineBreak.xml");

  @ParameterDescription(
      withDefault = true,
      description = "Absolute or relative path to key store in p12 format to sign TSLs with.")
  Path signer =
      Path.of("./testDataTemplates/certificates/ecc/trustAnchor/TSL-Signing-Unit-8-TEST-ONLY.p12");

  @ParameterDescription(
      withDefault = true,
      description = "Password used for the TSL signer key store.")
  String signerPassword = "00"; // NOSONAR
}
