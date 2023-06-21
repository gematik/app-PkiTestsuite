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

package de.gematik.pki.pkits.testsuite.unittests;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.pkits.testsuite.config.SshConfig;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.reporting.ListParameters;
import de.gematik.pki.pkits.testsuite.reporting.ListParameters.YamlLine;
import java.nio.file.Path;
import java.util.List;
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

  private static int getAllFieldsNumber(final Class<?> clazz) {
    final List<YamlLine> yamlLines = ListParameters.getFields(0, ".", clazz);
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

    final int testObject_sshConfig_port = 22;
    final String testObject_sshConfig_cryptMethod = "ECC";
    final long testObject_sshConfig_connectTimeoutSeconds = 4;
    final long testObject_sshConfig_authTimeoutSeconds = 4;
    final long testObject_sshConfig_channelOpenTimeoutSeconds = 4;
    final long testObject_sshConfig_channelCloseTimeoutSeconds = 4;

    final String ocspResponder_Id = "OCSP Responder";
    final String ocspResponder_AppPath = "./bin/pkits-ocsp-responder-exec.jar";

    final String tslProvider_id = "TSL Provider";
    final String tslProvider_appPath = "./bin/pkits-tsl-provider-exec.jar";

    final boolean testSuiteParameter_performInitialState = true;
    final boolean testSuiteParameter_CaptureNetworkTraffic = false;
    final Path testSuiteParameter_OcspSettings_KeystorePathOcsp =
        Path.of("./testDataTemplates/certificates/ecc/ocspKeystore");
    final String testSuiteParameter_OcspSettings_SignerPassword = "00";
    final int testSuiteParameter_OcspSettings_TimeoutDeltaMilliseconds = 1500;
    final int testSuiteParameter_OcspSettings_GracePeriodeExtraDelay = 5;

    final boolean testSuiteParameter_TslSettings_InitialStateTslImport = true;
    final Path testSuiteParameter_TslSettings_Signer =
        Path.of(
            "./testDataTemplates/certificates/ecc/trustAnchor/TSL-Signing-Unit-8-TEST-ONLY.p12");
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

    final SshConfig sshConfig = testSuiteConfig.getTestObject().getSshConfig();
    ca.assertEquals(testObject_sshConfig_port, sshConfig.getPort());
    ca.assertEquals(testObject_sshConfig_cryptMethod, sshConfig.getCryptMethod());
    ca.assertEquals(
        testObject_sshConfig_connectTimeoutSeconds, sshConfig.getConnectTimeoutSeconds());
    ca.assertEquals(testObject_sshConfig_authTimeoutSeconds, sshConfig.getAuthTimeoutSeconds());
    ca.assertEquals(
        testObject_sshConfig_channelOpenTimeoutSeconds, sshConfig.getChannelOpenTimeoutSeconds());
    ca.assertEquals(
        testObject_sshConfig_channelCloseTimeoutSeconds, sshConfig.getChannelCloseTimeoutSeconds());

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
        testSuiteParameter_TslSettings_Signer,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getSigner());
    ca.assertEquals(
        testSuiteParameter_TslSettings_SignerPassword,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getSignerPassword());
  }

  void testNonDefaultsInSshConfig(final TestSuiteConfig tscMinimal, final CustomAsserter ca) {

    // these parameters are optional and without default: they are not set in the tscMinimal
    final String testObject_sshConfig_username = "HasToBeDefined_username";
    final String testObject_sshConfig_password = "HasToBeDefined_password";
    final String testObject_sshConfig_host = "HasToBeDefined_host";
    final Path testObject_sshConfig_privateKey = Path.of("HasToBeDefined_privateKey");
    final String testObject_sshConfig_passphrase = "HasToBeDefined_privateKeyPassphrase";
    final String testObject_sshConfig_appDataHttpFwdSocket = "HasToBeDefined_appDataHttpFwdSocket";
    final Path testObject_sshConfig_filesToCopyRootDir =
        Path.of("HasToBeDefined_filesToCopyRootDir");
    final String testObject_sshConfig_filesToCopyPattern = "HasToBeDefined_filesToCopyPattern";
    final String testObject_sshConfig_remoteTargetDir = "HasToBeDefined_remoteTargetDir";
    final String testObject_sshConfig_remoteLogFile = "HasToBeDefined_remoteLogFile";

    final SshConfig sshConfig = tscMinimal.getTestObject().getSshConfig();
    ca.assertEquals(testObject_sshConfig_username, sshConfig.getUsername());
    ca.assertEquals(testObject_sshConfig_password, sshConfig.getPassword());
    ca.assertEquals(testObject_sshConfig_host, sshConfig.getHost());
    ca.assertEquals(testObject_sshConfig_privateKey, sshConfig.getPrivateKey());
    ca.assertEquals(testObject_sshConfig_passphrase, sshConfig.getPrivateKeyPassphrase());
    ca.assertEquals(testObject_sshConfig_appDataHttpFwdSocket, sshConfig.getAppDataHttpFwdSocket());
    ca.assertEquals(testObject_sshConfig_filesToCopyRootDir, sshConfig.getFilesToCopyRootDir());
    ca.assertEquals(testObject_sshConfig_filesToCopyPattern, sshConfig.getFilesToCopyPattern());
    ca.assertEquals(testObject_sshConfig_remoteTargetDir, sshConfig.getRemoteTargetDir());
    ca.assertEquals(testObject_sshConfig_remoteLogFile, sshConfig.getRemoteLogFile());
  }

  @Test
  void testDefaultsAndNonDefault() {
    // for better readability, we use underscores

    // definition of parameters without defaults

    // these parameters are optional and without default: they are not set in the tscMinimal
    final String testSuiteParameter_CaptureNetworkTraffic = "9.9.9.9";

    final String client_KeystorePathValidCerts =
        "./testDataTemplates/certificates/ecc/fachmodulClientCerts/valid";
    final String client_KeystorePathAlternativeCerts =
        "./testDataTemplates/certificates/ecc/fachmodulClientCerts/valid-alternative";
    final String client_KeystorePathInvalidCerts =
        "./testDataTemplates/certificates/ecc/fachmodulClientCerts/invalid";

    final String testObject_Name = "Server 0815";
    final String testObject_Type = "TlsServer";
    final String testObject_IpAddressOrFqdn = "127.0.0.1";
    final int testObject_Port = 8443;

    final int testObject_TslDownloadIntervalSeconds = 2;

    final String ocspResponder_IpAddressOrFqdn = "127.0.0.1";
    final int ocspResponder_Port = 8083;

    final String tslProvider_IpAddressOrFqdn = "127.0.0.1";
    final int tslProvider_Port = 8084;

    final Path yamlMinimal = Path.of("./docs/configs/inttest/pkits.yml");

    final TestSuiteConfig tscBlank = new TestSuiteConfig();
    final TestSuiteConfig tscMinimal = TestSuiteConfig.fromYaml(yamlMinimal);

    // overwrite with the default value
    tscMinimal
        .getTestObject()
        .setOcspGracePeriodSeconds(tscBlank.getTestObject().getOcspGracePeriodSeconds());
    tscMinimal
        .getTestObject()
        .setTslProcessingTimeSeconds(tscBlank.getTestObject().getTslProcessingTimeSeconds());
    tscMinimal.getTestSuiteParameter().setCaptureInterfaces("9.9.9.9");

    tscMinimal.getTestObject().getSshConfig().setUsername("HasToBeDefined_username");
    tscMinimal.getTestObject().getSshConfig().setPassword("HasToBeDefined_password");
    tscMinimal.getTestObject().getSshConfig().setHost("HasToBeDefined_host");
    tscMinimal.getTestObject().getSshConfig().setPrivateKey(Path.of("HasToBeDefined_privateKey"));
    tscMinimal
        .getTestObject()
        .getSshConfig()
        .setPrivateKeyPassphrase("HasToBeDefined_privateKeyPassphrase");
    tscMinimal
        .getTestObject()
        .getSshConfig()
        .setAppDataHttpFwdSocket("HasToBeDefined_appDataHttpFwdSocket");
    tscMinimal
        .getTestObject()
        .getSshConfig()
        .setFilesToCopyRootDir(Path.of("HasToBeDefined_filesToCopyRootDir"));
    tscMinimal
        .getTestObject()
        .getSshConfig()
        .setFilesToCopyPattern("HasToBeDefined_filesToCopyPattern");
    tscMinimal.getTestObject().getSshConfig().setRemoteTargetDir("HasToBeDefined_remoteTargetDir");
    tscMinimal.getTestObject().getSshConfig().setRemoteLogFile("HasToBeDefined_remoteLogFile");

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
        tscMinimal.getTestSuiteParameter().getCaptureInterfaces());

    testNonDefaultsInSshConfig(tscMinimal, ca);

    assertThat(ca.counter).as("23 parameters without defaults").isEqualTo(23);

    testDefaults(ca, tscMinimal);

    final int numberOfAllFields = getAllFieldsNumber(TestSuiteConfig.class);
    assertThat(ca.counter).isEqualTo(numberOfAllFields);

    final CustomAsserter caDefaults = new CustomAsserter();
    testDefaults(caDefaults, tscBlank);
  }

  void testAllFieldsAsNonDefaultInSshConfig(final CustomAsserter ca, final TestSuiteConfig tsc) {
    final String sshConfig_username = "testObject.sshConfig.username";
    final String sshConfig_password = "testObject.sshConfig.password";
    final String sshConfig_host = "testObject.sshConfig.host";
    final int sshConfig_port = -100;
    final Path sshConfig_privateKey = Path.of("testObject.sshConfig.privateKey");
    final String sshConfig_passphrase = "testObject.sshConfig.privateKeyPassphrase";
    final String sshConfig_appDataHttpFwdSocket = "testObject.sshConfig.appDataHttpFwdSocket";
    final String sshConfig_cryptMethod = "testObject.sshConfig.cryptMethod";
    final Path sshConfig_filesToCopyRootDir = Path.of("testObject.sshConfig.filesToCopyRootDir");
    final String sshConfig_filesToCopyPattern = "testObject.sshConfig.filesToCopyPattern";
    final String sshConfig_remoteTargetDir = "testObject.sshConfig.remoteTargetDir";
    final String sshConfig_remoteLogFile = "testObject.sshConfig.remoteLogFile";
    final long sshConfig_connectTimeoutSeconds = -200;
    final long sshConfig_authTimeoutSeconds = -300;
    final long sshConfig_channelOpenTimeoutSeconds = -400;
    final long sshConfig_channelCloseTimeoutSeconds = -500;

    final SshConfig sshConfig = tsc.getTestObject().getSshConfig();

    ca.assertEquals(sshConfig_username, sshConfig.getUsername());
    ca.assertEquals(sshConfig_password, sshConfig.getPassword());
    ca.assertEquals(sshConfig_host, sshConfig.getHost());
    ca.assertEquals(sshConfig_port, sshConfig.getPort());
    ca.assertEquals(sshConfig_privateKey, sshConfig.getPrivateKey());
    ca.assertEquals(sshConfig_passphrase, sshConfig.getPrivateKeyPassphrase());
    ca.assertEquals(sshConfig_appDataHttpFwdSocket, sshConfig.getAppDataHttpFwdSocket());
    ca.assertEquals(sshConfig_cryptMethod, sshConfig.getCryptMethod());
    ca.assertEquals(sshConfig_filesToCopyRootDir, sshConfig.getFilesToCopyRootDir());
    ca.assertEquals(sshConfig_filesToCopyPattern, sshConfig.getFilesToCopyPattern());
    ca.assertEquals(sshConfig_remoteTargetDir, sshConfig.getRemoteTargetDir());
    ca.assertEquals(sshConfig_remoteLogFile, sshConfig.getRemoteLogFile());
    ca.assertEquals(sshConfig_connectTimeoutSeconds, sshConfig.getConnectTimeoutSeconds());
    ca.assertEquals(sshConfig_authTimeoutSeconds, sshConfig.getAuthTimeoutSeconds());
    ca.assertEquals(sshConfig_channelOpenTimeoutSeconds, sshConfig.getChannelOpenTimeoutSeconds());
    ca.assertEquals(
        sshConfig_channelCloseTimeoutSeconds, sshConfig.getChannelCloseTimeoutSeconds());
  }

  @Test
  void testAllFieldsAsNonDefaults() { // NOSONAR

    final Path yamlAllParameters =
        Path.of("./pkits-testsuite/src/main/resources/all_pkits_parameters_unitTest.yml");
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
    final String testSuiteParameter_captureInterfaces = "testSuiteParameter.captureInterfaces";

    final Path testSuiteParameter_ocspSettings_KeystorePathOcsp =
        Path.of("testSuiteParameter.ocspSettings.keystorePathOcsp");
    final String testSuiteParameter_ocspSettings_SignerPassword =
        "testSuiteParameter.ocspSettings.signerPassword";
    final int testSuiteParameter_ocspSettings_TimeoutDeltaMilliseconds = -3000;
    final int testSuiteParameter_ocspSettings_GracePeriodExtraDelay = -1000;

    final boolean testSuiteParameter_TslSettings_InitialStateTslImport = false;
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
        testSuiteParameter_captureInterfaces, tsc.getTestSuiteParameter().getCaptureInterfaces());

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
        testSuiteParameter_TslSettings_Signer,
        tsc.getTestSuiteParameter().getTslSettings().getSigner());
    ca.assertEquals(
        testSuiteParameter_TslSettings_SignerPassword,
        tsc.getTestSuiteParameter().getTslSettings().getSignerPassword());

    testAllFieldsAsNonDefaultInSshConfig(ca, tsc);

    final int numberOfAllFields = getAllFieldsNumber(TestSuiteConfig.class);
    assertThat(ca.counter).isEqualTo(numberOfAllFields);
  }
}
