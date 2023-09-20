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

package de.gematik.pki.pkits.testsuite.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum TestObjectType {
  IDP_FACHDIENST(
      "IdpFachdienst",
      "fachmodulClient",
      UseCaseConnectionType.SCRIPT,
      PkitsTestDataConstants.DEFAULT_SMCB_CA,
      PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
      PkitsTestDataConstants.DEFAULT_SMCB_CA_RSA),

  INTERMEDIAER_SERVER(
      "IntermediaerServer",
      "fachmodulClientIntermediaer",
      UseCaseConnectionType.TLS_SERVER,
      PkitsTestDataConstants.DEFAULT_SMCB_CA,
      PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
      PkitsTestDataConstants.DEFAULT_SMCB_CA_RSA),

  KIM_FACHDIENST(
      "KimFachdienst",
      "kimClientModul",
      UseCaseConnectionType.TLS_SERVER,
      PkitsTestDataConstants.DEFAULT_KOMP_CA,
      PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
      PkitsTestDataConstants.DEFAULT_KOMP_CA_RSA),

  VSDM_FACHDIENST(
      "VsdmFachdienst",
      "intermediaerClient",
      UseCaseConnectionType.TLS_SERVER,
      PkitsTestDataConstants.DEFAULT_KOMP_CA,
      PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
      PkitsTestDataConstants.DEFAULT_KOMP_CA_RSA),

  VPN_KONZENTRATOR(
      "VpnKonzentrator",
      "netzkonnektorClient",
      UseCaseConnectionType.SCRIPT_OVER_SSH,
      PkitsTestDataConstants.DEFAULT_KOMP_CA,
      PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
      PkitsTestDataConstants.DEFAULT_KOMP_CA_RSA),

  VPN_REG_SERVER(
      "VpnRegServer",
      "fachmodulClient",
      UseCaseConnectionType.TLS_SERVER,
      PkitsTestDataConstants.DEFAULT_SMCB_CA,
      PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
      PkitsTestDataConstants.DEFAULT_SMCB_CA_RSA);

  private static final Map<String, TestObjectType> typeNamesMap = new TreeMap<>();

  static {
    for (final TestObjectType testObjectType : TestObjectType.values()) {
      typeNamesMap.put(testObjectType.typeName, testObjectType);
    }
  }

  final String typeName;

  final String directory;

  final UseCaseConnectionType connectionType;

  /** path to default issuer certificate */
  final Path clientDefaultIssuerCertPath;

  /** path to alternative issuer certificate */
  final Path clientAlternativeIssuerCertPath;

  /** path to default issuer RSA certificate */
  final Path clientDefaultIssuerRsaCertPath;

  @JsonCreator
  public static TestObjectType forValue(final String value) {
    final TestObjectType testObjectType = typeNamesMap.get(value);
    if (testObjectType == null) {
      throw new TestSuiteException(
          "unknown value <%s> for TestObjectType. Allowed values: %s."
              .formatted(value, String.join(", ", typeNamesMap.keySet())));
    }
    return testObjectType;
  }

  @JsonValue
  public String getTypeName() {
    return typeName;
  }

  /**
   * @return path to valid key store end-entity files in p12 format for the tests
   */
  public Path getClientKeystorePathValidCerts() {
    return Path.of("./testDataTemplates/certificates/ecc/%s/valid".formatted(directory));
  }

  /**
   * @return path to valid key store end-entity files in p12 format for the tests
   */
  public Path getClientKeystorePathAlternativeCerts() {
    return Path.of(
        "./testDataTemplates/certificates/ecc/%s/valid-alternative".formatted(directory));
  }

  /**
   * @return path to invalid key store end-entity files in p12 format for the tests
   */
  public Path getClientKeystorePathInvalidCerts() {
    return Path.of("./testDataTemplates/certificates/ecc/%s/invalid".formatted(directory));
  }

  public Path getClientKeystorePathRsaCerts() {
    return Path.of("./testDataTemplates/certificates/rsa/%s".formatted(directory));
  }
}
