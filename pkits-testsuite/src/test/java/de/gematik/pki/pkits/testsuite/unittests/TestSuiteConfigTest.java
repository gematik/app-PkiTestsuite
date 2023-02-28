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

package de.gematik.pki.pkits.testsuite.unittests;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.config.ParameterDescription;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

class TestSuiteConfigTest {

  @Test
  void getTestSuiteConfig() {
    assertDoesNotThrow(TestConfigManager::getTestSuiteConfig);
  }

  @Test
  void readStringFromConfig() {
    final TestSuiteConfig testSuiteConfig = TestConfigManager.getTestSuiteConfig();
    assertThat(testSuiteConfig.getClient().getKeystorePathValidCerts()).contains("valid");
  }

  @Test
  void readBooleanFromConfig() {
    assertThat(
            TestConfigManager.getTestSuiteConfig().getTestSuiteParameter().isPerformInitialState())
        .isInstanceOf(Boolean.class);
  }

  @Getter
  static class YamlLine {
    private final int level;
    private final String path;
    private final Field field;
    private final boolean isEnd;
    private final String description;
    private final boolean withDefault;

    public YamlLine(final int level, final String path, final Field field, final boolean isEnd) {
      this.level = level;
      this.path = path;
      this.field = field;
      this.isEnd = isEnd;

      final ParameterDescription parameterDescription =
          this.field.getAnnotation(ParameterDescription.class);
      if (parameterDescription != null) {
        this.description = parameterDescription.description();
        this.withDefault = parameterDescription.withDefault();
      } else {
        this.description = "";
        this.withDefault = false;
      }
    }

    public boolean hasDescription() {
      return StringUtils.isNotBlank(description);
    }

    public boolean isFieldStringLike() {
      final Class<?> fieldClazz = field.getType();
      return fieldClazz.equals(String.class) || fieldClazz.equals(Path.class);
    }

    public String getLineForYaml() {
      final String valueStr;
      String prefix = "";
      if (isEnd) {
        final Class<?> clazz = field.getDeclaringClass();
        if (withDefault) {
          try {
            final Object obj = clazz.getDeclaredConstructor().newInstance();
            field.setAccessible(true);

            final Object value = field.get(obj);
            if (isFieldStringLike()) {
              valueStr = " \"%s\"".formatted(value);
            } else {
              valueStr = " " + value;
            }
          } catch (final NoSuchMethodException
              | InvocationTargetException
              | InstantiationException
              | IllegalAccessException e) {
            throw new PkiCommonException(
                "Cannot generate instance of " + clazz.getCanonicalName(), e);
          }

        } else {
          if (isFieldStringLike()) {
            valueStr = " \"HasToBeDefined_%s\"".formatted(field.getName());
          } else {
            valueStr = " HasToBeDefined_" + field.getName();
          }
        }

      } else {
        valueStr = "";
        prefix = "\n";
      }

      return prefix + StringUtils.repeat("  ", level) + field.getName() + ":" + valueStr;
    }

    public String getLineForYamlWithDescription(final int spacePads) {
      if (!isEnd) {
        return getLineForYaml();
      }

      final String formatStr = String.format("%%__-%d__s# %%s", spacePads).replace("_", "");
      if (hasDescription()) {
        return formatStr.formatted(getLineForYaml(), description);
      } else {
        return formatStr.formatted(getLineForYaml(), "");
      }
    }
  }

  static boolean isEnd(final Class<?> fieldClazz) {
    return fieldClazz.isPrimitive()
        || fieldClazz.equals(String.class)
        || fieldClazz.equals(Path.class)
        || fieldClazz.equals(Integer.class);
  }

  private static List<YamlLine> getFields(
      final int level, final String parentPath, final Class<?> clazz) {
    final Field[] fields = clazz.getDeclaredFields();

    final List<YamlLine> yamlLines = new ArrayList<>();
    for (final Field field : fields) {

      final Class<?> fieldClazz = field.getType();
      final String path = parentPath + "." + field.getName();
      final String message =
          "field %s of type %s in class %s: processing of the type is not implemented"
              .formatted(field.getName(), fieldClazz.getCanonicalName(), clazz.getCanonicalName());

      if (isEnd(fieldClazz)) {
        yamlLines.add(new YamlLine(level, path, field, true));

      } else if (fieldClazz.getCanonicalName().startsWith("de.gematik")) {
        yamlLines.add(new YamlLine(level, path, field, false));
        yamlLines.addAll(getFields(level + 1, path, fieldClazz));

      } else if (fieldClazz.isArray()) {
        throw new IllegalArgumentException(message);

      } else if (fieldClazz.isEnum()) {

        throw new IllegalArgumentException(message);

      } else {
        throw new IllegalArgumentException(message);
      }
    }

    return yamlLines;
  }

  private static int getAllFieldsNumber(final Class<?> clazz) {
    final List<YamlLine> yamlLines = getFields(0, ".", clazz);
    return yamlLines.stream().filter(YamlLine::isEnd).toList().size();
  }

  private static class CustomAsserter {
    int counter = 0;

    <T> void assertEquals(final T expected, final T actual) {
      assertThat(actual).isEqualTo(expected);
      ++counter;
    }
  }

  private void testDefaults(final CustomAsserter ca, final TestSuiteConfig testSuiteConfig) {

    // for better readability, we use underscores

    // definition of default parameters
    final String client_KeystorePassword = "00";

    final String testObject_ScriptPath = "unused by default";
    final int testObject_OcspGracePeriodSeconds = 30;
    final int testObject_TslProcessingTimeSeconds = 3;
    final int testObject_OcspTimeoutSeconds = 10;

    final String ocspResponder_Id = "OCSP Responder";
    final String ocspResponder_AppPath =
        "../pkits-ocsp-responder/target/pkits-ocsp-responder-exec.jar";

    final String tslProvider_id = "TSL Provider";
    final String tslProvider_appPath = "../pkits-tsl-provider/target/pkits-tsl-provider-exec.jar";

    final boolean testSuiteParameter_performInitialState = true;
    final boolean testSuiteParameter_CaptureNetworkTraffic = false;
    final Path testSuiteParameter_OcspSettings_KeystorePathOcsp =
        Path.of("../testDataTemplates/certificates/ecc/ocspKeystore");
    final String testSuiteParameter_OcspSettings_SignerPassword = "00";
    final int testSuiteParameter_OcspSettings_TimeoutDeltaMilliseconds = 1500;
    final int testSuiteParameter_OcspSettings_GracePeriodeExtraDelay = 5;

    final boolean testSuiteParameter_TslSettings_InitialStateTslImport = true;
    final Path testSuiteParameter_TslSettings_DefaultTemplate =
        Path.of("../testDataTemplates/tsl/TSL_default.xml");
    final Path testSuiteParameter_TslSettings_AlternativeTemplate =
        Path.of("../testDataTemplates/tsl/TSL_altCA.xml");
    final Path testSuiteParameter_TslSettings_DefectAlternativeCaBrokenTemplate =
        Path.of("../testDataTemplates/tsl/TSL_defect_altCA_broken.xml");
    final Path testSuiteParameter_TslSettings_DefectAlternativeCaUnspecifiedTemplate =
        Path.of("../testDataTemplates/tsl/TSL_defect_unspecified-CA_altCA.xml");
    final Path testSuiteParameter_TslSettings_DefectAlternativeCaWrongSrvInfoExtTemplate =
        Path.of("../testDataTemplates/tsl/TSL_defect_altCA_wrong-srvInfoExt.xml");
    final Path testSuiteParameter_TslSettings_AlternativeCaUnspecifiedStiTemplate =
        Path.of("../testDataTemplates/tsl/TSL_altCA_unspecifiedSTI.xml");
    final Path testSuiteParameter_TslSettings_AlternativeRevokedTemplate =
        Path.of("../testDataTemplates/tsl/TSL_altCA_revoked.xml");
    final Path testSuiteParameter_TslSettings_AlternativeNoLineBreakTemplate =
        Path.of("../testDataTemplates/tsl/TSL_altCA_noLineBreak.xml");
    final Path testSuiteParameter_TslSettings_Signer =
        Path.of(
            "../testDataTemplates/certificates/ecc/trustAnchor/TSL-Signing-Unit-8-TEST-ONLY.p12");
    final String testSuiteParameter_TslSettings_SignerPassword = "00";

    ca.assertEquals(client_KeystorePassword, testSuiteConfig.getClient().getKeystorePassword());

    ca.assertEquals(testObject_ScriptPath, testSuiteConfig.getTestObject().getScriptPath());
    ca.assertEquals(
        testObject_TslProcessingTimeSeconds,
        testSuiteConfig.getTestObject().getTslProcessingTimeSeconds());
    ca.assertEquals(
        testObject_OcspGracePeriodSeconds,
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds());
    ca.assertEquals(
        testObject_OcspTimeoutSeconds, testSuiteConfig.getTestObject().getOcspTimeoutSeconds());

    ca.assertEquals(ocspResponder_Id, testSuiteConfig.getOcspResponder().getId());
    ca.assertEquals(ocspResponder_AppPath, testSuiteConfig.getOcspResponder().getAppPath());

    ca.assertEquals(tslProvider_id, testSuiteConfig.getTslProvider().getId());
    ca.assertEquals(tslProvider_appPath, testSuiteConfig.getTslProvider().getAppPath());

    ca.assertEquals(
        testSuiteParameter_performInitialState,
        testSuiteConfig.getTestSuiteParameter().isPerformInitialState());
    ca.assertEquals(
        testSuiteParameter_CaptureNetworkTraffic,
        testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic());

    ca.assertEquals(
        testSuiteParameter_OcspSettings_KeystorePathOcsp,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getKeystorePathOcsp());
    ca.assertEquals(
        testSuiteParameter_OcspSettings_SignerPassword,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getSignerPassword());
    ca.assertEquals(
        testSuiteParameter_OcspSettings_TimeoutDeltaMilliseconds,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getTimeoutDeltaMilliseconds());
    ca.assertEquals(
        testSuiteParameter_OcspSettings_GracePeriodeExtraDelay,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getGracePeriodExtraDelay());

    ca.assertEquals(
        testSuiteParameter_TslSettings_InitialStateTslImport,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().isInitialStateTslImport());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefaultTemplate,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getDefaultTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeTemplate,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getAlternativeTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefectAlternativeCaBrokenTemplate,
        testSuiteConfig
            .getTestSuiteParameter()
            .getTslSettings()
            .getDefectAlternativeCaBrokenTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefectAlternativeCaUnspecifiedTemplate,
        testSuiteConfig
            .getTestSuiteParameter()
            .getTslSettings()
            .getDefectAlternativeCaUnspecifiedTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefectAlternativeCaWrongSrvInfoExtTemplate,
        testSuiteConfig
            .getTestSuiteParameter()
            .getTslSettings()
            .getDefectAlternativeCaWrongSrvInfoExtTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeCaUnspecifiedStiTemplate,
        testSuiteConfig
            .getTestSuiteParameter()
            .getTslSettings()
            .getAlternativeCaUnspecifiedStiTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeRevokedTemplate,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getAlternativeRevokedTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeNoLineBreakTemplate,
        testSuiteConfig
            .getTestSuiteParameter()
            .getTslSettings()
            .getAlternativeNoLineBreakTemplate());

    ca.assertEquals(
        testSuiteParameter_TslSettings_Signer,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getSigner());
    ca.assertEquals(
        testSuiteParameter_TslSettings_SignerPassword,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getSignerPassword());
  }

  @Test
  void testDefaultsAndNonDefault() {
    // for better readability, we use underscores

    // definition of parameters without defaults

    // captureNetworkTraffic is optional, and set manually in tscMinimal
    final String testSuiteParameter_CaptureNetworkTraffic = "9.9.9.9";

    final String client_KeystorePathValidCerts =
        "../testDataTemplates/certificates/ecc/fachmodul_clientCerts/valid";
    final String client_KeystorePathAlternativeCerts =
        "../testDataTemplates/certificates/ecc/fachmodul_clientCerts/valid-alternative";
    final String client_KeystorePathInvalidCerts =
        "../testDataTemplates/certificates/ecc/fachmodul_clientCerts/invalid";

    final String testObject_Name = "Server 0815";
    final String testObject_Type = "TlsServer";
    final String testObject_IpAddressOrFqdn = "127.0.0.1";
    final int testObject_Port = 8443;

    final int testObject_TslDownloadIntervalSeconds = 2;

    final String ocspResponder_IpAddressOrFqdn = "127.0.0.1";
    final int ocspResponder_Port = 8083;

    final String tslProvider_IpAddressOrFqdn = "127.0.0.1";
    final int tslProvider_Port = 8084;

    final Path yamlMinimal = Path.of("../docs/configs/inttest/pkits.yml");

    final TestSuiteConfig tscBlank = new TestSuiteConfig();
    final TestSuiteConfig tscMinimal = TestSuiteConfig.fromYaml(yamlMinimal);

    // overwrite with the default value
    tscMinimal
        .getTestObject()
        .setOcspGracePeriodSeconds(tscBlank.getTestObject().getOcspGracePeriodSeconds());
    tscMinimal
        .getTestObject()
        .setTslProcessingTimeSeconds(tscBlank.getTestObject().getTslProcessingTimeSeconds());
    tscMinimal.getTestSuiteParameter().setCaptureInterface("9.9.9.9");

    final CustomAsserter ca = new CustomAsserter();

    ca.assertEquals(
        client_KeystorePathInvalidCerts, tscMinimal.getClient().getKeystorePathInvalidCerts());
    ca.assertEquals(
        client_KeystorePathValidCerts, tscMinimal.getClient().getKeystorePathValidCerts());
    ca.assertEquals(
        client_KeystorePathAlternativeCerts,
        tscMinimal.getClient().getKeystorePathAlternativeCerts());
    ca.assertEquals(testObject_Name, tscMinimal.getTestObject().getName());
    ca.assertEquals(testObject_Type, tscMinimal.getTestObject().getType());
    ca.assertEquals(testObject_IpAddressOrFqdn, tscMinimal.getTestObject().getIpAddressOrFqdn());
    ca.assertEquals(testObject_Port, tscMinimal.getTestObject().getPort());
    ca.assertEquals(
        testObject_TslDownloadIntervalSeconds,
        tscMinimal.getTestObject().getTslDownloadIntervalSeconds());
    ca.assertEquals(
        ocspResponder_IpAddressOrFqdn, tscMinimal.getOcspResponder().getIpAddressOrFqdn());
    ca.assertEquals(ocspResponder_Port, tscMinimal.getOcspResponder().getPort());
    ca.assertEquals(tslProvider_IpAddressOrFqdn, tscMinimal.getTslProvider().getIpAddressOrFqdn());
    ca.assertEquals(tslProvider_Port, tscMinimal.getTslProvider().getPort());
    ca.assertEquals(
        testSuiteParameter_CaptureNetworkTraffic,
        tscMinimal.getTestSuiteParameter().getCaptureInterface());

    assertThat(ca.counter).as("13 parameters without defaults").isEqualTo(13);

    testDefaults(ca, tscMinimal);
    final int numberOfAllFields = getAllFieldsNumber(TestSuiteConfig.class);
    assertThat(ca.counter).isEqualTo(numberOfAllFields);

    final CustomAsserter caDefaults = new CustomAsserter();
    testDefaults(caDefaults, tscBlank);
  }

  @Test
  void testAllFieldsAsNonDefaults() { // NOSONAR

    final Path yamlAllParameters =
        Path.of("./src/test/resources/all_pkits_parameters_unitTest.yml");
    final TestSuiteConfig tsc = TestSuiteConfig.fromYaml(yamlAllParameters);

    // for readability, we use underscores

    final String client_KeystorePathValidCerts = "client.keystorePathValidCerts";
    final String client_KeystorePathAlternativeCerts = "client.keystorePathAlternativeCerts";
    final String client_KeystorePathInvalidCerts = "client.keystorePathInvalidCerts";
    final String client_KeystorePassword = "client.keystorePassword";
    final String testObject_Name = "testObject.name";
    final String testObject_Type = "testObject.type";
    final String testObject_IpAddressOrFqdn = "testObject.ipAddressOrFqdn";
    final int testObject_Port = -99;
    final String testObject_ScriptPath = "testObject.scriptPath";
    final int testObject_TslDownloadIntervalSeconds = -100;
    final int testObject_TslProcessingTimeSeconds = -200;
    final int testObject_OcspGracePeriodSeconds = -300;
    final int testObject_OcspTimeoutSeconds = -400;

    final String ocspResponder_IpAddressOrFqdn = "ocspResponder.ipAddressOrFqdn";
    final int ocspResponder_Port = -1000;
    final String ocspResponder_Id = "ocspResponder.id";
    final String ocspResponder_AppPath = "ocspResponder.appPath";

    final String tslProvider_IpAddressOrFqdn = "tslProvider.ipAddressOrFqdn";
    final int tslProvider_Port = -2000;
    final String tslProvider_Id = "tslProvider.id";
    final String tslProvider_AppPath = "tslProvider.appPath";

    final boolean testSuiteParameter_performInitialState = false;
    final boolean testSuiteParameter_captureNetworkTraffic = true;
    final String testSuiteParameter_captureInterface = "testSuiteParameter.captureInterface";

    final Path testSuiteParameter_ocspSettings_KeystorePathOcsp =
        Path.of("testSuiteParameter.ocspSettings.keystorePathOcsp");
    final String testSuiteParameter_ocspSettings_SignerPassword =
        "testSuiteParameter.ocspSettings.signerPassword";
    final int testSuiteParameter_ocspSettings_TimeoutDeltaMilliseconds = -3000;
    final int testSuiteParameter_ocspSettings_GracePeriodExtraDelay = -1000;

    final boolean testSuiteParameter_TslSettings_InitialStateTslImport = false;
    final Path testSuiteParameter_TslSettings_DefaultTemplate =
        Path.of("testSuiteParameter.tslSettings.defaultTemplate");
    final Path testSuiteParameter_TslSettings_AlternativeTemplate =
        Path.of("testSuiteParameter.tslSettings.alternativeTemplate");
    final Path testSuiteParameter_TslSettings_DefectAlternativeCaBrokenTemplate =
        Path.of("../testDataTemplates/tsl/TSL_defect_altCA_broken.xml");
    final Path testSuiteParameter_TslSettings_DefectAlternativeCaUnspecifiedTemplate =
        Path.of("../testDataTemplates/tsl/TSL_defect_unspecified-CA_altCA.xml");
    final Path testSuiteParameter_TslSettings_DefectAlternativeCaWrongSrvInfoExtTemplate =
        Path.of("../testDataTemplates/tsl/TSL_defect_altCA_wrong-srvInfoExt.xml");
    final Path testSuiteParameter_TslSettings_AlternativeCaUnspecifiedStiTemplate =
        Path.of("../testDataTemplates/tsl/TSL_altCA_unspecifiedSTI.xml");
    final Path testSuiteParameter_TslSettings_AlternativeRevokedTemplate =
        Path.of("testSuiteParameter.tslSettings.alternativeRevokedTemplate");
    final Path testSuiteParameter_TslSettings_AlternativeNoLineBreakTemplate =
        Path.of("testSuiteParameter.tslSettings.alternativeNoLineBreakTemplate");
    final Path testSuiteParameter_TslSettings_Signer =
        Path.of("testSuiteParameter.tslSettings.signer");
    final String testSuiteParameter_TslSettings_SignerPassword =
        "testSuiteParameter.tslSettings.signerPassword";

    final CustomAsserter ca = new CustomAsserter();
    ca.assertEquals(client_KeystorePathValidCerts, tsc.getClient().getKeystorePathValidCerts());
    ca.assertEquals(
        client_KeystorePathAlternativeCerts, tsc.getClient().getKeystorePathAlternativeCerts());
    ca.assertEquals(client_KeystorePathInvalidCerts, tsc.getClient().getKeystorePathInvalidCerts());
    ca.assertEquals(client_KeystorePassword, tsc.getClient().getKeystorePassword());

    ca.assertEquals(testObject_Name, tsc.getTestObject().getName());
    ca.assertEquals(testObject_Type, tsc.getTestObject().getType());
    ca.assertEquals(testObject_IpAddressOrFqdn, tsc.getTestObject().getIpAddressOrFqdn());
    ca.assertEquals(testObject_Port, tsc.getTestObject().getPort());
    ca.assertEquals(testObject_ScriptPath, tsc.getTestObject().getScriptPath());
    ca.assertEquals(
        testObject_TslDownloadIntervalSeconds, tsc.getTestObject().getTslDownloadIntervalSeconds());
    ca.assertEquals(
        testObject_TslProcessingTimeSeconds, tsc.getTestObject().getTslProcessingTimeSeconds());
    ca.assertEquals(
        testObject_OcspGracePeriodSeconds, tsc.getTestObject().getOcspGracePeriodSeconds());
    ca.assertEquals(testObject_OcspTimeoutSeconds, tsc.getTestObject().getOcspTimeoutSeconds());

    ca.assertEquals(ocspResponder_IpAddressOrFqdn, tsc.getOcspResponder().getIpAddressOrFqdn());
    ca.assertEquals(ocspResponder_Port, tsc.getOcspResponder().getPort());
    ca.assertEquals(ocspResponder_Id, tsc.getOcspResponder().getId());
    ca.assertEquals(ocspResponder_AppPath, tsc.getOcspResponder().getAppPath());

    ca.assertEquals(tslProvider_IpAddressOrFqdn, tsc.getTslProvider().getIpAddressOrFqdn());
    ca.assertEquals(tslProvider_Port, tsc.getTslProvider().getPort());
    ca.assertEquals(tslProvider_Id, tsc.getTslProvider().getId());
    ca.assertEquals(tslProvider_AppPath, tsc.getTslProvider().getAppPath());

    ca.assertEquals(
        testSuiteParameter_performInitialState,
        tsc.getTestSuiteParameter().isPerformInitialState());
    ca.assertEquals(
        testSuiteParameter_captureNetworkTraffic,
        tsc.getTestSuiteParameter().isCaptureNetworkTraffic());
    ca.assertEquals(
        testSuiteParameter_captureInterface, tsc.getTestSuiteParameter().getCaptureInterface());

    ca.assertEquals(
        testSuiteParameter_ocspSettings_KeystorePathOcsp,
        tsc.getTestSuiteParameter().getOcspSettings().getKeystorePathOcsp());
    ca.assertEquals(
        testSuiteParameter_ocspSettings_SignerPassword,
        tsc.getTestSuiteParameter().getOcspSettings().getSignerPassword());
    ca.assertEquals(
        testSuiteParameter_ocspSettings_TimeoutDeltaMilliseconds,
        tsc.getTestSuiteParameter().getOcspSettings().getTimeoutDeltaMilliseconds());
    ca.assertEquals(
        testSuiteParameter_ocspSettings_GracePeriodExtraDelay,
        tsc.getTestSuiteParameter().getOcspSettings().getGracePeriodExtraDelay());

    ca.assertEquals(
        testSuiteParameter_TslSettings_InitialStateTslImport,
        tsc.getTestSuiteParameter().getTslSettings().isInitialStateTslImport());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefaultTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getDefaultTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getAlternativeTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefectAlternativeCaBrokenTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getDefectAlternativeCaBrokenTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefectAlternativeCaUnspecifiedTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getDefectAlternativeCaUnspecifiedTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_DefectAlternativeCaWrongSrvInfoExtTemplate,
        tsc.getTestSuiteParameter()
            .getTslSettings()
            .getDefectAlternativeCaWrongSrvInfoExtTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeCaUnspecifiedStiTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getAlternativeCaUnspecifiedStiTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeRevokedTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getAlternativeRevokedTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_AlternativeNoLineBreakTemplate,
        tsc.getTestSuiteParameter().getTslSettings().getAlternativeNoLineBreakTemplate());
    ca.assertEquals(
        testSuiteParameter_TslSettings_Signer,
        tsc.getTestSuiteParameter().getTslSettings().getSigner());
    ca.assertEquals(
        testSuiteParameter_TslSettings_SignerPassword,
        tsc.getTestSuiteParameter().getTslSettings().getSignerPassword());

    final int numberOfAllFields = getAllFieldsNumber(TestSuiteConfig.class);
    assertThat(ca.counter).isEqualTo(numberOfAllFields);
  }

  @Test
  void generateConfigWithAllParameters() {
    final List<YamlLine> yamlLines = getFields(0, ".", TestSuiteConfig.class);

    final int padSize = 90;

    final List<String> lines =
        yamlLines.stream()
            .map(yamlLine -> yamlLine.getLineForYamlWithDescription(padSize))
            .toList();

    final String content = String.join("\n", lines) + "\n";

    assertDoesNotThrow(
        () -> Files.writeString(Path.of("../docs/all_pkits_parameters.yml"), content));
  }
}
