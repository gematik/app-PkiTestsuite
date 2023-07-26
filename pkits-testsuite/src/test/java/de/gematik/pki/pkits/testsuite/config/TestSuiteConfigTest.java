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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.pkits.testsuite.reporting.ListParameters;
import java.nio.file.Path;
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

  private static class CustomAsserter {
    int counter = 0;

    <T> void assertEquals(final T expected, final T actual) {
      assertThat(actual).isEqualTo(expected);
      ++counter;
    }
  }

  private void testSshConfigDefaults(final CustomAsserter ca, final SshConfig sshConfig) {

    final int port = 22;
    final long connectTimeoutSeconds = 60;
    final long authTimeoutSeconds = 60;
    final long channelOpenTimeoutSeconds = 60;
    final long channelCloseTimeoutSeconds = 60;

    ca.assertEquals(port, sshConfig.getPort());
    ca.assertEquals(connectTimeoutSeconds, sshConfig.getConnectTimeoutSeconds());
    ca.assertEquals(authTimeoutSeconds, sshConfig.getAuthTimeoutSeconds());
    ca.assertEquals(channelOpenTimeoutSeconds, sshConfig.getChannelOpenTimeoutSeconds());
    ca.assertEquals(channelCloseTimeoutSeconds, sshConfig.getChannelCloseTimeoutSeconds());
  }

  private void testDefaults(final CustomAsserter ca, final TestSuiteConfig testSuiteConfig) {

    // for better readability, we use underscores

    // definition of default parameters
    final String client_keystorePassword = "00";

    final String testObject_scriptPath = "unused by default";
    final int testObject_ocspGracePeriodSeconds = 30;
    final int testObject_tslProcessingTimeSeconds = 3;
    final int testObject_ocspProcessingTimeSeconds = 1;
    final int testObject_tslGracePeriodDays = 0;
    final int testObject_ocspTimeoutSeconds = 10;

    final boolean testObject_scriptUseCase_sendReceiveApplicationData = true;
    final String testObject_scriptUseCase_cryptMethod = "ECC";

    final String ocspResponder_id = "OCSP Responder";
    final String ocspResponder_appPath = "./bin/pkits-ocsp-responder-exec.jar";

    final String tslProvider_id = "TSL Provider";
    final String tslProvider_appPath = "./bin/pkits-tsl-provider-exec.jar";

    final boolean testSuiteParameter_performInitialState = true;
    final boolean testSuiteParameter_captureNetworkTraffic = false;
    final Path testSuiteParameter_ocspSettings_keystorePathOcsp =
        Path.of("./testDataTemplates/certificates/ecc/ocspKeystore");
    final String testSuiteParameter_ocspSettings_signerPassword = "00";
    final int testSuiteParameter_ocspSettings_timeoutDeltaMilliseconds = 1500;
    final int testSuiteParameter_ocspSettings_gracePeriodeExtraDelay = 5;

    final boolean testSuiteParameter_tslSettings_initialStateTslImport = true;
    final Path testSuiteParameter_tslSettings_signer =
        Path.of(
            "./testDataTemplates/certificates/ecc/trustAnchor/TSL-Signing-Unit-8-TEST-ONLY.p12");
    final String testSuiteParameter_tslSettings_signerPassword = "00";

    ca.assertEquals(client_keystorePassword, testSuiteConfig.getClient().getKeystorePassword());

    ca.assertEquals(
        testObject_scriptPath, testSuiteConfig.getTestObject().getScriptUseCase().getScriptPath());
    ca.assertEquals(
        testObject_tslProcessingTimeSeconds,
        testSuiteConfig.getTestObject().getTslProcessingTimeSeconds());
    ca.assertEquals(
        testObject_ocspProcessingTimeSeconds,
        testSuiteConfig.getTestObject().getOcspProcessingTimeSeconds());
    ca.assertEquals(
        testObject_tslGracePeriodDays, testSuiteConfig.getTestObject().getTslGracePeriodDays());
    ca.assertEquals(
        testObject_ocspGracePeriodSeconds,
        testSuiteConfig.getTestObject().getOcspGracePeriodSeconds());
    ca.assertEquals(
        testObject_ocspTimeoutSeconds, testSuiteConfig.getTestObject().getOcspTimeoutSeconds());

    testSshConfigDefaults(ca, testSuiteConfig.getSshConfig());

    final ScriptUseCase scriptUseCase = testSuiteConfig.getTestObject().getScriptUseCase();
    ca.assertEquals(
        testObject_scriptUseCase_sendReceiveApplicationData,
        scriptUseCase.isSendReceiveApplicationData());
    ca.assertEquals(testObject_scriptUseCase_cryptMethod, scriptUseCase.getCryptMethod());

    ca.assertEquals(ocspResponder_id, testSuiteConfig.getOcspResponder().getId());
    ca.assertEquals(ocspResponder_appPath, testSuiteConfig.getOcspResponder().getAppPath());

    ca.assertEquals(tslProvider_id, testSuiteConfig.getTslProvider().getId());
    ca.assertEquals(tslProvider_appPath, testSuiteConfig.getTslProvider().getAppPath());

    ca.assertEquals(
        testSuiteParameter_performInitialState,
        testSuiteConfig.getTestSuiteParameter().isPerformInitialState());
    ca.assertEquals(
        testSuiteParameter_captureNetworkTraffic,
        testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic());

    ca.assertEquals(
        testSuiteParameter_ocspSettings_keystorePathOcsp,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getKeystorePathOcsp());
    ca.assertEquals(
        testSuiteParameter_ocspSettings_signerPassword,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getSignerPassword());
    ca.assertEquals(
        testSuiteParameter_ocspSettings_timeoutDeltaMilliseconds,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getTimeoutDeltaMilliseconds());
    ca.assertEquals(
        testSuiteParameter_ocspSettings_gracePeriodeExtraDelay,
        testSuiteConfig.getTestSuiteParameter().getOcspSettings().getGracePeriodExtraDelay());

    ca.assertEquals(
        testSuiteParameter_tslSettings_initialStateTslImport,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().isInitialStateTslImport());

    ca.assertEquals(
        testSuiteParameter_tslSettings_signer,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getSigner());
    ca.assertEquals(
        testSuiteParameter_tslSettings_signerPassword,
        testSuiteConfig.getTestSuiteParameter().getTslSettings().getSignerPassword());
  }

  void testNonDefaultsInSshConfig(final CustomAsserter ca, final SshConfig sshConfig) {

    // these parameters are optional and without defaults: they are not set in the tscMinimal
    final String sshConfig_username = "HasToBeDefined_username";
    final String sshConfig_password = "HasToBeDefined_password";
    final String sshConfig_host = "HasToBeDefined_host";
    final Path sshConfig_privateKey = Path.of("HasToBeDefined_privateKey");
    final String sshConfig_passphrase = "HasToBeDefined_privateKeyPassphrase";

    final Path sshUseCaseParameters_filesToCopyRootDir =
        Path.of("HasToBeDefined_filesToCopyRootDir");
    final String sshUseCaseParameters_filesToCopyPattern = "HasToBeDefined_filesToCopyPattern";
    final String sshUseCaseParameters_remoteTargetDir = "HasToBeDefined_remoteTargetDir";
    final String sshUseCaseParameters_remoteLogFile = "HasToBeDefined_remoteLogFile";

    final SshUseCaseParameters sshUseCaseParameters = sshConfig.getSshUseCaseParameters();

    ca.assertEquals(sshConfig_username, sshConfig.getUsername());
    ca.assertEquals(sshConfig_password, sshConfig.getPassword());
    ca.assertEquals(sshConfig_host, sshConfig.getHost());
    ca.assertEquals(sshConfig_privateKey, sshConfig.getPrivateKey());
    ca.assertEquals(sshConfig_passphrase, sshConfig.getPrivateKeyPassphrase());

    ca.assertEquals(
        sshUseCaseParameters_filesToCopyRootDir, sshUseCaseParameters.getFilesToCopyRootDir());
    ca.assertEquals(
        sshUseCaseParameters_filesToCopyPattern, sshUseCaseParameters.getFilesToCopyPattern());
    ca.assertEquals(
        sshUseCaseParameters_remoteTargetDir, sshUseCaseParameters.getRemoteTargetDir());
    ca.assertEquals(sshUseCaseParameters_remoteLogFile, sshUseCaseParameters.getRemoteLogFile());
  }

  private void setNonDefaultValues(final TestSuiteConfig tscMinimal) {

    tscMinimal
        .getTestObject()
        .getScriptUseCase()
        .setAppDataHttpFwdSocket("HasToBeDefined_appDataHttpFwdSocket");

    final SshConfig sshConfig = tscMinimal.getSshConfig();

    sshConfig.setUsername("HasToBeDefined_username");
    sshConfig.setPassword("HasToBeDefined_password");
    sshConfig.setHost("HasToBeDefined_host");
    sshConfig.setPrivateKey(Path.of("HasToBeDefined_privateKey"));
    sshConfig.setPrivateKeyPassphrase("HasToBeDefined_privateKeyPassphrase");
    sshConfig
        .getSshUseCaseParameters()
        .setFilesToCopyRootDir(Path.of("HasToBeDefined_filesToCopyRootDir"));
    sshConfig.getSshUseCaseParameters().setFilesToCopyPattern("HasToBeDefined_filesToCopyPattern");
    sshConfig.getSshUseCaseParameters().setRemoteTargetDir("HasToBeDefined_remoteTargetDir");
    sshConfig.getSshUseCaseParameters().setRemoteLogFile("HasToBeDefined_remoteLogFile");
  }

  @Test
  void testDefaultsAndNonDefaults() {

    // these parameters are optional and without defaults: they are not set in the tscMinimal
    final String testSuiteParameter_captureNetworkTraffic = "9.9.9.9";

    final String client_keystorePathValidCerts =
        "./testDataTemplates/certificates/ecc/fachmodulClient/valid";
    final String client_keystorePathAlternativeCerts =
        "./testDataTemplates/certificates/ecc/fachmodulClient/valid-alternative";
    final String client_keystorePathInvalidCerts =
        "./testDataTemplates/certificates/ecc/fachmodulClient/invalid";

    // definition of parameters without defaults
    final String testObject_name = "Server 0815";
    final String testObject_type = "TlsServer";
    final String testObject_ipAddressOrFqdn = "127.0.0.1";
    final int testObject_port = 8443;

    final int testObject_tslDownloadIntervalSeconds = 2;

    final String ocspResponder_ipAddressOrFqdn = "127.0.0.1";
    final int ocspResponder_port = 8083;

    final String tslProvider_ipAddressOrFqdn = "127.0.0.1";
    final int tslProvider_port = 8084;

    final String testObject_scriptUseCase__appDataHttpFwdSocket =
        "HasToBeDefined_appDataHttpFwdSocket";

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

    setNonDefaultValues(tscMinimal);

    final CustomAsserter ca = new CustomAsserter();

    ca.assertEquals(
        client_keystorePathInvalidCerts, tscMinimal.getClient().getKeystorePathInvalidCerts());
    ca.assertEquals(
        client_keystorePathValidCerts, tscMinimal.getClient().getKeystorePathValidCerts());
    ca.assertEquals(
        client_keystorePathAlternativeCerts,
        tscMinimal.getClient().getKeystorePathAlternativeCerts());
    ca.assertEquals(testObject_name, tscMinimal.getTestObject().getName());
    ca.assertEquals(testObject_type, tscMinimal.getTestObject().getType());
    ca.assertEquals(testObject_ipAddressOrFqdn, tscMinimal.getTestObject().getIpAddressOrFqdn());
    ca.assertEquals(testObject_port, tscMinimal.getTestObject().getPort());
    ca.assertEquals(
        testObject_tslDownloadIntervalSeconds,
        tscMinimal.getTestObject().getTslDownloadIntervalSeconds());

    ca.assertEquals(
        ocspResponder_ipAddressOrFqdn, tscMinimal.getOcspResponder().getIpAddressOrFqdn());
    ca.assertEquals(ocspResponder_port, tscMinimal.getOcspResponder().getPort());
    ca.assertEquals(tslProvider_ipAddressOrFqdn, tscMinimal.getTslProvider().getIpAddressOrFqdn());
    ca.assertEquals(tslProvider_port, tscMinimal.getTslProvider().getPort());
    ca.assertEquals(
        testSuiteParameter_captureNetworkTraffic,
        tscMinimal.getTestSuiteParameter().getCaptureInterfaces());
    ca.assertEquals(
        testObject_scriptUseCase__appDataHttpFwdSocket,
        tscMinimal.getTestObject().getScriptUseCase().getAppDataHttpFwdSocket());

    testNonDefaultsInSshConfig(ca, tscMinimal.getSshConfig());

    assertThat(ca.counter).as("23 parameters without defaults").isEqualTo(23);

    testDefaults(ca, tscMinimal);

    final int numberOfAllFields = ListParameters.getNumberOfAllFields(TestSuiteConfig.class);
    assertThat(ca.counter).isEqualTo(numberOfAllFields);

    final CustomAsserter caDefaults = new CustomAsserter();
    testDefaults(caDefaults, tscBlank);
  }

  private void testAllFieldsAsNonDefaultClient(
      final CustomAsserter ca, final ClientConfig clientConfig) {
    final String keystorePathValidCerts = "client.keystorePathValidCerts";
    final String keystorePathAlternativeCerts = "client.keystorePathAlternativeCerts";
    final String keystorePathInvalidCerts = "client.keystorePathInvalidCerts";
    final String keystorePassword = "client.keystorePassword";

    ca.assertEquals(keystorePathValidCerts, clientConfig.getKeystorePathValidCerts());
    ca.assertEquals(keystorePathAlternativeCerts, clientConfig.getKeystorePathAlternativeCerts());
    ca.assertEquals(keystorePathInvalidCerts, clientConfig.getKeystorePathInvalidCerts());
    ca.assertEquals(keystorePassword, clientConfig.getKeystorePassword());
  }

  private void testAllFieldsAsNonDefaultOcspResponderAndTslProvider(
      final CustomAsserter ca, final TestSuiteConfig tsc) {

    final String ocspResponder_ipAddressOrFqdn = "ocspResponder.ipAddressOrFqdn";
    final int ocspResponder_port = -1000;
    final String ocspResponder_id = "ocspResponder.id";
    final String ocspResponder_appPath = "ocspResponder.appPath";

    final String tslProvider_ipAddressOrFqdn = "tslProvider.ipAddressOrFqdn";
    final int tslProvider_port = -2000;
    final String tslProvider_id = "tslProvider.id";
    final String tslProvider_appPath = "tslProvider.appPath";

    ca.assertEquals(ocspResponder_ipAddressOrFqdn, tsc.getOcspResponder().getIpAddressOrFqdn());
    ca.assertEquals(ocspResponder_port, tsc.getOcspResponder().getPort());
    ca.assertEquals(ocspResponder_id, tsc.getOcspResponder().getId());
    ca.assertEquals(ocspResponder_appPath, tsc.getOcspResponder().getAppPath());

    ca.assertEquals(tslProvider_ipAddressOrFqdn, tsc.getTslProvider().getIpAddressOrFqdn());
    ca.assertEquals(tslProvider_port, tsc.getTslProvider().getPort());
    ca.assertEquals(tslProvider_id, tsc.getTslProvider().getId());
    ca.assertEquals(tslProvider_appPath, tsc.getTslProvider().getAppPath());
  }

  private void testAllFieldsAsNonDefaultTestSuiteParameters(
      final CustomAsserter ca, final TestSuiteParameter testSuiteParameter) {

    final boolean performInitialState = false;
    final boolean captureNetworkTraffic = true;
    final String captureInterfaces = "testSuiteParameter.captureInterfaces";

    final Path ocspSettings_keystorePathOcsp =
        Path.of("testSuiteParameter.ocspSettings.keystorePathOcsp");
    final String ocspSettings_signerPassword = "testSuiteParameter.ocspSettings.signerPassword";
    final int ocspSettings_timeoutDeltaMilliseconds = -3000;
    final int ocspSettings_gracePeriodExtraDelay = -1000;

    final boolean tslSettings_initialStateTslImport = false;
    final Path tslSettings_signer = Path.of("testSuiteParameter.tslSettings.signer");
    final String tslSettings_signerPassword = "testSuiteParameter.tslSettings.signerPassword";

    ca.assertEquals(performInitialState, testSuiteParameter.isPerformInitialState());
    ca.assertEquals(captureNetworkTraffic, testSuiteParameter.isCaptureNetworkTraffic());
    ca.assertEquals(captureInterfaces, testSuiteParameter.getCaptureInterfaces());

    ca.assertEquals(
        ocspSettings_keystorePathOcsp, testSuiteParameter.getOcspSettings().getKeystorePathOcsp());
    ca.assertEquals(
        ocspSettings_signerPassword, testSuiteParameter.getOcspSettings().getSignerPassword());
    ca.assertEquals(
        ocspSettings_timeoutDeltaMilliseconds,
        testSuiteParameter.getOcspSettings().getTimeoutDeltaMilliseconds());
    ca.assertEquals(
        ocspSettings_gracePeriodExtraDelay,
        testSuiteParameter.getOcspSettings().getGracePeriodExtraDelay());

    ca.assertEquals(
        tslSettings_initialStateTslImport,
        testSuiteParameter.getTslSettings().isInitialStateTslImport());

    ca.assertEquals(tslSettings_signer, testSuiteParameter.getTslSettings().getSigner());
    ca.assertEquals(
        tslSettings_signerPassword, testSuiteParameter.getTslSettings().getSignerPassword());
  }

  private void testAllFieldsAsNonDefaultTestObject(
      final CustomAsserter ca, final TestObjectConfig testObject) {

    final String name = "testObject.name";
    final String type = "testObject.type";
    final String ipAddressOrFqdn = "testObject.ipAddressOrFqdn";
    final int port = -99;
    final int tslDownloadIntervalSeconds = -100;
    final int tslGracePeriodDays = -150;
    final int tslProcessingTimeSeconds = -200;
    final int ocspProcessingTimeSeconds = -250;
    final int ocspGracePeriodSeconds = -300;
    final int ocspTimeoutSeconds = -400;

    final String scriptUseCase_scriptPath = "testObject.scriptUseCase.scriptPath";
    final boolean scriptUseCase_sendReceiveApplicationData = false;
    final String scriptUseCase_appDataHttpFwdSocket =
        "testObject.scriptUseCase.appDataHttpFwdSocket";
    final String scriptUseCase_cryptMethod = "testObject.scriptUseCase.cryptMethod";

    ca.assertEquals(name, testObject.getName());
    ca.assertEquals(type, testObject.getType());
    ca.assertEquals(ipAddressOrFqdn, testObject.getIpAddressOrFqdn());
    ca.assertEquals(port, testObject.getPort());
    ca.assertEquals(scriptUseCase_scriptPath, testObject.getScriptUseCase().getScriptPath());
    ca.assertEquals(tslDownloadIntervalSeconds, testObject.getTslDownloadIntervalSeconds());
    ca.assertEquals(tslGracePeriodDays, testObject.getTslGracePeriodDays());
    ca.assertEquals(tslProcessingTimeSeconds, testObject.getTslProcessingTimeSeconds());
    ca.assertEquals(ocspProcessingTimeSeconds, testObject.getOcspProcessingTimeSeconds());
    ca.assertEquals(ocspGracePeriodSeconds, testObject.getOcspGracePeriodSeconds());
    ca.assertEquals(ocspTimeoutSeconds, testObject.getOcspTimeoutSeconds());

    final ScriptUseCase scriptUseCase = testObject.getScriptUseCase();
    ca.assertEquals(
        scriptUseCase_sendReceiveApplicationData, scriptUseCase.isSendReceiveApplicationData());
    ca.assertEquals(scriptUseCase_appDataHttpFwdSocket, scriptUseCase.getAppDataHttpFwdSocket());
    ca.assertEquals(scriptUseCase_cryptMethod, scriptUseCase.getCryptMethod());
  }

  void testAllFieldsAsNonDefaultSshConfig(final CustomAsserter ca, final SshConfig sshConfig) {
    final String sshConfig_username = "sshConfig.username";
    final String sshConfig_password = "sshConfig.password";
    final String sshConfig_host = "sshConfig.host";
    final int sshConfig_port = -100;
    final Path sshConfig_privateKey = Path.of("sshConfig.privateKey");
    final String sshConfig_passphrase = "sshConfig.privateKeyPassphrase";

    final Path sshUseCaseParameters_filesToCopyRootDir =
        Path.of("sshConfig.sshUseCaseParameters.filesToCopyRootDir");
    final String sshUseCaseParameters_filesToCopyPattern =
        "sshConfig.sshUseCaseParameters.filesToCopyPattern";
    final String sshUseCaseParameters_remoteTargetDir =
        "sshConfig.sshUseCaseParameters.remoteTargetDir";
    final String sshUseCaseParameters_remoteLogFile =
        "sshConfig.sshUseCaseParameters.remoteLogFile";

    final long sshConfig_connectTimeoutSeconds = -200;
    final long sshConfig_authTimeoutSeconds = -300;
    final long sshConfig_channelOpenTimeoutSeconds = -400;
    final long sshConfig_channelCloseTimeoutSeconds = -500;

    ca.assertEquals(sshConfig_username, sshConfig.getUsername());
    ca.assertEquals(sshConfig_password, sshConfig.getPassword());
    ca.assertEquals(sshConfig_host, sshConfig.getHost());
    ca.assertEquals(sshConfig_port, sshConfig.getPort());
    ca.assertEquals(sshConfig_privateKey, sshConfig.getPrivateKey());
    ca.assertEquals(sshConfig_passphrase, sshConfig.getPrivateKeyPassphrase());
    ca.assertEquals(sshConfig_connectTimeoutSeconds, sshConfig.getConnectTimeoutSeconds());
    ca.assertEquals(sshConfig_authTimeoutSeconds, sshConfig.getAuthTimeoutSeconds());
    ca.assertEquals(sshConfig_channelOpenTimeoutSeconds, sshConfig.getChannelOpenTimeoutSeconds());
    ca.assertEquals(
        sshConfig_channelCloseTimeoutSeconds, sshConfig.getChannelCloseTimeoutSeconds());

    final SshUseCaseParameters sshUseCaseParameters = sshConfig.getSshUseCaseParameters();

    ca.assertEquals(
        sshUseCaseParameters_filesToCopyRootDir, sshUseCaseParameters.getFilesToCopyRootDir());
    ca.assertEquals(
        sshUseCaseParameters_filesToCopyPattern, sshUseCaseParameters.getFilesToCopyPattern());
    ca.assertEquals(
        sshUseCaseParameters_remoteTargetDir, sshUseCaseParameters.getRemoteTargetDir());
    ca.assertEquals(sshUseCaseParameters_remoteLogFile, sshUseCaseParameters.getRemoteLogFile());
  }

  @Test
  void testAllFieldsAsNonDefaults() {

    final Path yamlAllParameters =
        Path.of("./pkits-testsuite/src/main/resources/all_pkits_parameters_unitTest.yml");

    final TestSuiteConfig tsc = TestSuiteConfig.fromYaml(yamlAllParameters);

    final CustomAsserter ca = new CustomAsserter();

    testAllFieldsAsNonDefaultClient(ca, tsc.getClient());
    testAllFieldsAsNonDefaultTestObject(ca, tsc.getTestObject());
    testAllFieldsAsNonDefaultSshConfig(ca, tsc.getSshConfig());
    testAllFieldsAsNonDefaultOcspResponderAndTslProvider(ca, tsc);

    testAllFieldsAsNonDefaultTestSuiteParameters(ca, tsc.getTestSuiteParameter());

    final int numberOfAllFields = ListParameters.getNumberOfAllFields(TestSuiteConfig.class);

    assertThat(ca.counter).isEqualTo(numberOfAllFields);
  }
}
