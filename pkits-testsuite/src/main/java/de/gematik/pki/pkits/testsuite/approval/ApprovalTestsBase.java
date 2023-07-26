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

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.gemlibpki.utils.P12Reader.getContentFromP12;
import static de.gematik.pki.pkits.common.PkitsCommonUtils.waitSeconds;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator.NO_TSL_MODIFICATIONS;
import static de.gematik.pki.pkits.testsuite.usecases.OcspResponderType.OCSP_RESP_WITH_PROVIDED_CERT;
import static de.gematik.pki.pkits.testsuite.usecases.UseCaseResult.USECASE_VALID;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.OcspResponderConfigDtoBuilder;
import de.gematik.pki.pkits.testsuite.common.CertificateProvider;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.DtoDateConfigOption;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.TslSequenceNr;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerator;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.CreateTslTemplate;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.OcspSettings;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.config.TslSettings;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.pcap.PcapHelper;
import de.gematik.pki.pkits.testsuite.pcap.PcapManager;
import de.gematik.pki.pkits.testsuite.reporting.CurrentTestInfo;
import de.gematik.pki.pkits.testsuite.reporting.CustomTestExecutionListener;
import de.gematik.pki.pkits.testsuite.reporting.TestResultLoggerExtension;
import de.gematik.pki.pkits.testsuite.simulators.OcspResponderInstance;
import de.gematik.pki.pkits.testsuite.simulators.TslProviderInstance;
import de.gematik.pki.pkits.testsuite.testutils.InitialStateTest;
import de.gematik.pki.pkits.testsuite.testutils.InitialTestDataTest;
import de.gematik.pki.pkits.testsuite.testutils.TslTaSwitchUtils;
import de.gematik.pki.pkits.testsuite.usecases.OcspResponderType;
import de.gematik.pki.pkits.testsuite.usecases.UseCase;
import de.gematik.pki.pkits.testsuite.usecases.UseCaseResult;
import de.gematik.pki.pkits.tsl.provider.api.TslDownloadEndpointType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.awaitility.core.ConditionTimeoutException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

@Slf4j
@DisplayName("Base class for all PKI approval tests.")
@TestMethodOrder(OrderAnnotation.class)
@ExtendWith(TestResultLoggerExtension.class)
public abstract class ApprovalTestsBase {

  public static final List<Class<?>> ALL_TESTS_CLASSES =
      List.of(
          CertificateApprovalTests.class,
          OcspApprovalTests.class,
          TslApprovalTests.class,
          TslSignerApprovalTests.class,
          TslTaApprovalTests.class,
          InitialStateTest.class,
          InitialTestDataTest.class,
          TslApprovalExtraTests.class,
          TslTaSwitchUtils.class);

  protected static final UseCaseConfig WITHOUT_USECASE = null;

  protected static final String OFFERING_TSL_WITH_SEQNR_MESSAGE =
      "Offering TSL with tslSeqNr {} for download.";

  public static final String OUT_LOGS_DIRNAME = "./out/logs/";
  protected static String clientKeystorePassw;
  protected static String ocspRespUri;
  protected static String tslProvUri;
  protected static OcspSettings ocspSettings;
  protected static TslSettings tslSettings;

  protected static Path defaultTslSigner;
  protected static String tslSignerKeystorePassw;

  protected static P12Container defaultOcspSigner;

  protected static final TestSuiteConfig testSuiteConfig = TestConfigManager.getTestSuiteConfig();
  private static final int WEB_SERVER_START_TIMEOUT_SECS = 30;
  protected static TslSequenceNr tslSequenceNr;

  private PcapManager pcapManager = null;

  protected CurrentTestInfo currentTestInfo;

  void failNotImplemented() {
    fail("not implemented");
  }

  protected static final String TA_NAME_DEFAULT = "default";
  protected static final String TA_NAME_ALT1 = "first alternative";
  protected static final String TA_NAME_ALT2 = "second alternative";

  protected static String getSwitchMessage(final String anchorType1, final String anchorType2) {
    return "Offer a TSL to switch from the %s trust anchor to the %s trust anchor."
        .formatted(anchorType1, anchorType2);
  }

  @BeforeAll
  static void setupBeforeAll() {
    log.debug("ApprovalTest(s) started.");
    tslSequenceNr = TslSequenceNr.getInstance();

    final int sutServerPort =
        getSutServerPortFromEnvironment().orElse(testSuiteConfig.getTestObject().getPort());
    testSuiteConfig.getTestObject().setPort(sutServerPort);
    clientKeystorePassw = testSuiteConfig.getClient().getKeystorePassword();

    OcspResponderInstance.getInstance().startServer();
    TslProviderInstance.getInstance().startServer();

    ocspRespUri =
        OcspResponderInstance.getInstance().waitUntilWebServerIsUp(WEB_SERVER_START_TIMEOUT_SECS);
    log.info("OcspResponderInstance: {}", ocspRespUri);
    tslProvUri =
        TslProviderInstance.getInstance().waitUntilWebServerIsUp(WEB_SERVER_START_TIMEOUT_SECS);
    log.info("TslProviderInstance: {}", tslProvUri);

    ocspSettings = testSuiteConfig.getTestSuiteParameter().getOcspSettings();

    tslSettings = testSuiteConfig.getTestSuiteParameter().getTslSettings();
    defaultTslSigner = tslSettings.getSigner();
    tslSignerKeystorePassw = tslSettings.getSignerPassword();

    defaultOcspSigner =
        getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(TestSuiteConstants.OCSP_SIGNER_FILENAME),
            ocspSettings.getSignerPassword());

    log.info(
        "TestObject: {}:{}", testSuiteConfig.getTestObject().getIpAddressOrFqdn(), sutServerPort);

    if (testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic()) {
      try {
        PcapHelper.assignDevices(testSuiteConfig);
      } catch (final Exception e) {
        log.error("problems occurred when assigning devices to sniff", e);
      }
    }
  }

  @BeforeEach
  void setupBeforeEach(final TestInfo testInfo) {

    currentTestInfo = new CurrentTestInfo(testInfo);

    testCaseMessage();

    if (!TestResultLoggerExtension.canContinueExecutionOfRemainingTests()) {

      final String message =
          "\n\nstopped execution of remaining tests as one of the previous tests failed: "
              + TestResultLoggerExtension.getStopExecutionOfRemainingTestsReason()
              + "\n\n";

      log.error("Aborting the test case");
      log.error(message);

      Assumptions.abort(message);
    }

    if (testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic()) {
      pcapManager =
          new PcapManager(
              PcapHelper.getPcapService(),
              PcapHelper.getPcapDeviceCommonInfos(),
              OUT_LOGS_DIRNAME,
              testInfo,
              true);
      pcapManager.start();
    }
  }

  @AfterEach
  void tearDownAfterEach() {

    log.info(
        """

            =======================================================================================
            =  End of test case - {}
            =======================================================================================
            =======================================================================================


            """,
        currentTestInfo);

    if (testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic()
        || (pcapManager != null)) {
      pcapManager.stop();
      pcapManager.close();
      pcapManager.createGzipFile();
      pcapManager.deletePcapFile();
      pcapManager = null;
    }

    currentTestInfo = null;
  }

  @AfterAll
  static void tearDownAfterAll() {

    if (CustomTestExecutionListener.isStopComponentsClassAfterAll()) {
      OcspResponderInstance.getInstance().stopServer();
      TslProviderInstance.getInstance().stopServer();
    }
    log.debug("ApprovalTest(s) finished.");
  }

  protected void testCaseMessage() {
    log.info(
        """



            =======================================================================================
            =======================================================================================
            = Starting test case: {}
            =======================================================================================

            """,
        currentTestInfo);

    Arrays.stream(
            currentTestInfo
                .getTestInfo()
                .getTestMethod()
                .orElseThrow()
                .getAnnotationsByType(Afo.class))
        .toList()
        .forEach(afo -> log.info("{} - {}", afo.afoId(), afo.description()));
  }

  public static Function<TestSuiteConfig, Integer> getShortTimeoutAndDelayFunc() {
    return timeoutAndDelayFuncMap.get("shortDelay");
  }

  public static Function<TestSuiteConfig, Integer> getLongTimeoutAndDelayFunc() {
    return timeoutAndDelayFuncMap.get("longDelay");
  }

  private static final Map<String, Function<TestSuiteConfig, Integer>> timeoutAndDelayFuncMap =
      Map.of(
          "shortDelay",
          config ->
              config.getTestObject().getOcspTimeoutSeconds() * 1000
                  - config.getTestSuiteParameter().getOcspSettings().getTimeoutDeltaMilliseconds(),
          "longDelay",
          config ->
              config.getTestObject().getOcspTimeoutSeconds() * 1000
                  + config.getTestSuiteParameter().getOcspSettings().getTimeoutDeltaMilliseconds());

  public static Consumer<OcspResponderConfigDtoBuilder> getDtoDateConfigStep(
      final DtoDateConfigOption dateConfigOption, final int deltaMilliseconds) {

    return switch (dateConfigOption) {
      case THIS_UPDATE -> dtoBuilder -> dtoBuilder.thisUpdateDeltaMilliseconds(deltaMilliseconds);
      case PRODUCED_AT -> dtoBuilder -> dtoBuilder.producedAtDeltaMilliseconds(deltaMilliseconds);
      case NEXT_UPDATE -> dtoBuilder -> dtoBuilder.nextUpdateDeltaMilliseconds(deltaMilliseconds);
    };
  }

  protected void establishDefaultTrustStoreAndExecuteUseCase() {
    if (testSuiteConfig.getTestSuiteParameter().isPerformInitialState()
        && !tslSettings.isInitialStateTslImport()) {
      updateTrustStore(
          "Offer the default TSL.",
          newTslGenerator("defaultTsl").getStandardTslDownload(CreateTslTemplate.defaultTsl()),
          OCSP_REQUEST_EXPECT,
          WITHOUT_USECASE);
    }

    useCaseWithCert(
        getPathOfFirstValidCert(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  protected void initialState() {

    if (!testSuiteConfig.getTestSuiteParameter().isPerformInitialState()) {
      log.info("\n\n===> Initial state use case skipped by user request. - {}\n", currentTestInfo);
      return;
    }

    if (tslSettings.isInitialStateTslImport()) {
      log.info("\n\n===> Establishing initial state... - {}\n", currentTestInfo);
      initialTslDownloadByTestObject();

      useCaseWithCert(
          true,
          getPathOfFirstValidCert(),
          USECASE_VALID,
          OCSP_RESP_WITH_PROVIDED_CERT,
          OCSP_REQUEST_EXPECT);

      log.info("\n\n===> Initial state successful! - {}\n\n", currentTestInfo);

    } else {
      tslSequenceNr.setExpectedNrInTestObject(tslSequenceNr.getCurrentNrInTestObject());
      log.info("updated expectedNrInTestObject: {}", tslSequenceNr);
      log.info("\n===> Initial state TSL import skipped by user request. - {}\n", currentTestInfo);
    }
  }

  protected TslGenerator newTslGenerator() {
    return newTslGenerator("", NO_TSL_MODIFICATIONS);
  }

  protected TslGenerator newTslGenerator(final String tslName) {
    return newTslGenerator(tslName, NO_TSL_MODIFICATIONS);
  }

  protected TslGenerator newTslGenerator(final String tslName, final TslOperation modifyTsl) {
    return TslGenerator.builder()
        .currentTestInfo(currentTestInfo)
        .tslName(tslName)
        .tslSigner(getDefaultTslSignerP12())
        .ocspSigner(defaultOcspSigner)
        .tslDownloadIntervalSeconds(getTslDownloadIntervalWithExtraTimeSeconds())
        .tslProcessingTimeSeconds(testSuiteConfig.getTestObject().getTslProcessingTimeSeconds())
        .ocspProcessingTimeSeconds(testSuiteConfig.getTestObject().getOcspProcessingTimeSeconds())
        .tslProvUri(tslProvUri)
        .ocspRespUri(ocspRespUri)
        .tslSeqNr(tslSequenceNr.getNextTslSeqNr())
        .modifyTsl(modifyTsl)
        .build();
  }

  private TslDownload initialStateWithTemplate(
      final String tslName, final TrustStatusListType tslTemplate) {

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();

    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);

    log.info("Start initial TSL download: tslName {}, tslSeqNr {}.", tslName, offeredTslSeqNr);
    final TslDownload tslDownload = newTslGenerator(tslName).getStandardTslDownload(tslTemplate);

    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(IGNORE_SEQUENCE_NUMBER, IGNORE_SEQUENCE_NUMBER);
    tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);

    log.info("Finished initial TSL download: tslName {}, tslSeqNr {}.", tslName, offeredTslSeqNr);

    return tslDownload;
  }

  protected TslDownload initialTslDownloadByTestObject() {
    return initialStateWithTemplate("initialTslDownload", CreateTslTemplate.defaultTsl());
  }

  void initialStateWithAlternativeTemplate() {

    initialStateWithTemplate(
        "initialStateWithAlternativeTemplate", CreateTslTemplate.alternativeTsl());

    useCaseWithCert(
        getPathOfAlternativeCertificate(),
        USECASE_VALID,
        OCSP_RESP_WITH_PROVIDED_CERT,
        OCSP_REQUEST_EXPECT);
  }

  @AllArgsConstructor
  static class UseCaseConfig {

    Path useCaseCertPath;
    UseCaseResult useCaseResult;
    OcspResponderType ocspResponderType;
    OcspRequestExpectationBehaviour ocspRequestExpectationBehaviourForUseCase;
  }

  protected UseCaseConfig withUseCase(
      final Path useCaseCertPath, final UseCaseResult useCaseResult) {
    return new UseCaseConfig(useCaseCertPath, useCaseResult, OCSP_RESP_WITH_PROVIDED_CERT, null);
  }

  protected UseCaseConfig withUseCase(
      final Path useCaseCertPath,
      final UseCaseResult useCaseResult,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviourForUseCase) {
    return new UseCaseConfig(
        useCaseCertPath,
        useCaseResult,
        OCSP_RESP_WITH_PROVIDED_CERT,
        ocspRequestExpectationBehaviourForUseCase);
  }

  protected void updateTrustStore(
      final String description,
      final TslDownload tslDownload,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour,
      final UseCaseConfig useCaseConfig) {

    log.info(
        "START updateTrustStore -\n  description: {},\n  {}\n",
        description,
        PkitsTestSuiteUtils.getCallerTrace());

    final int offeredTslSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info(OFFERING_TSL_WITH_SEQNR_MESSAGE, offeredTslSeqNr);

    verifyUpdateTrustStore(offeredTslSeqNr, tslDownload, ocspRequestExpectationBehaviour);

    if (useCaseConfig == WITHOUT_USECASE) {
      log.info(
          "END updateTrustStore (without useCaseResult) -\n  description: {},\n  {}\n",
          description,
          PkitsTestSuiteUtils.getCallerTrace());
      return;
    }

    useCaseInUpdateTrustStore(useCaseConfig);

    log.info(
        "END updateTrustStore (with useCaseResult) -\n  description: {},\n  {}\n",
        description,
        PkitsTestSuiteUtils.getCallerTrace());
  }

  private void verifyUpdateTrustStore(
      final int offeredTslSeqNr,
      final TslDownload tslDownload,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {

    tslDownload.configureOcspResponderForTslSigner();
    tslSequenceNr.setLastOfferedTslSeqNr(offeredTslSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());

    if (ocspRequestExpectationBehaviour == OCSP_REQUEST_EXPECT) {
      tslDownload.waitUntilOcspRequestForTslSigner(tslSequenceNr.getExpectedNrInTestObject());
      tslSequenceNr.setExpectedNrInTestObject(offeredTslSeqNr);
    } else if (ocspRequestExpectationBehaviour == OCSP_REQUEST_IGNORE) {
      tslDownload.waitUntilOcspRequestForSignerOptional();
    } else {
      assertNoOcspRequest(tslDownload);
    }
  }

  private void useCaseInUpdateTrustStore(@NonNull final UseCaseConfig useCaseConfig) {

    final OcspRequestExpectationBehaviour ocspRequestExpectation;
    if (useCaseConfig.useCaseResult == USECASE_VALID) {
      ocspRequestExpectation =
          ObjectUtils.defaultIfNull(
              useCaseConfig.ocspRequestExpectationBehaviourForUseCase, OCSP_REQUEST_EXPECT);
    } else {
      ocspRequestExpectation =
          ObjectUtils.defaultIfNull(
              useCaseConfig.ocspRequestExpectationBehaviourForUseCase, OCSP_REQUEST_DO_NOT_EXPECT);
    }

    useCaseWithCert(
        useCaseConfig.useCaseCertPath,
        useCaseConfig.useCaseResult,
        useCaseConfig.ocspResponderType,
        ocspRequestExpectation);
  }

  /**
   * @param certPath path to the certificate to use
   * @param useCaseResult expected result for the use case
   * @param ocspResponderType configuration of ocsp responder
   * @param ocspRequestExpectationBehaviour expect ocsp request
   */
  protected void useCaseWithCert(
      @NonNull final Path certPath,
      final UseCaseResult useCaseResult,
      final OcspResponderType ocspResponderType,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {
    useCaseWithCert(
        false, certPath, useCaseResult, ocspResponderType, ocspRequestExpectationBehaviour);
  }

  void configureOcspResponder(@NonNull final Path certPath) {
    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(defaultOcspSigner)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
  }

  /**
   * @param isInitialState is true, if the method called as a part of initial state before the
   *     actual test execution
   * @param certPath path to the certificate to use
   * @param useCaseResult expected result for the use case
   * @param ocspResponderType configuration of ocsp responder
   * @param ocspRequestExpectationBehaviour expect ocsp request
   */
  private void useCaseWithCert(
      final boolean isInitialState,
      @NonNull final Path certPath,
      final UseCaseResult useCaseResult,
      final OcspResponderType ocspResponderType,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {

    if (!isInitialState) {
      log.info(
          """
              ----->
              START - useCaseWithCert for
                {}
                {} with parameters
                certPath {},
                {},  {},  {}

              """,
          currentTestInfo,
          PkitsTestSuiteUtils.getCallerTrace(),
          certPath,
          useCaseResult,
          ocspResponderType,
          ocspRequestExpectationBehaviour);
    }

    if (ocspResponderType == OCSP_RESP_WITH_PROVIDED_CERT) {
      configureOcspResponder(certPath);
    }

    waitForOcspCacheToExpire();

    final String message =
        "\"%s\" in useCaseWithCert for %s with parameters%n  %s%n  %s%n  %s%n"
            .formatted(
                useCaseResult.getMessage(),
                currentTestInfo,
                useCaseResult,
                ocspResponderType,
                ocspRequestExpectationBehaviour);

    assertThat(UseCase.exec(certPath, testSuiteConfig))
        .as(message)
        .isEqualTo(useCaseResult.getExpectedReturnCode());

    log.info("{}", tslSequenceNr);
    final Optional<Integer> rxMaxTslSeqNr =
        checkOcspHistory(
            CertReader.getX509FromP12(certPath, clientKeystorePassw).getSerialNumber(),
            tslSequenceNr,
            ocspRequestExpectationBehaviour);

    rxMaxTslSeqNr.ifPresent(tslSequenceNr::saveCurrentTestObjectTslSeqNr);

    log.info("{}", tslSequenceNr);
    if (!isInitialState) {

      log.info(
          """
              <-----
              SUCCESSFULLY completed useCaseWithCert for
                {}
                {} with parameters
                certPath {},
                {},  {},  {}

              """,
          currentTestInfo,
          PkitsTestSuiteUtils.getCallerTrace(),
          certPath,
          useCaseResult,
          ocspResponderType,
          ocspRequestExpectationBehaviour);
    }
  }

  protected void assertNoOcspRequest(final TslDownload tslDownload) {
    final String expectedMessagePrefix =
        "Timeout for event \"OcspRequestHistoryHasEntry for tslSeqNr -1 and TSL signer cert %s\""
            .formatted(tslDownload.getTslSignerCert().getSerialNumber());

    assertThatThrownBy(tslDownload::waitUntilOcspRequestForTslSigner)
        .isInstanceOf(TestSuiteException.class)
        .hasMessageStartingWith(expectedMessagePrefix)
        .cause()
        .isInstanceOf(ConditionTimeoutException.class)
        .hasMessage(
            "Condition with de.gematik.pki.pkits.testsuite.common.ocsp.OcspRequestHistoryContainer was not fulfilled within %s seconds."
                .formatted(testSuiteConfig.getTestObject().getTslProcessingTimeSeconds()));

    log.info(
        "As expected, observed an TestSuiteException with message <{}>", expectedMessagePrefix);
  }

  protected void waitForOcspCacheToExpire() {
    final int seconds = testSuiteConfig.getTestObject().getOcspGracePeriodSeconds();
    waitForOcspCacheToExpire(seconds);
  }

  protected void waitForOcspCacheToExpire(int seconds) {
    seconds = seconds + ocspSettings.getGracePeriodExtraDelay();
    log.info("Waiting for ocsp cache to expire.");
    waitSeconds(seconds);
  }

  protected Path getPathOfFirstValidCert() {
    return getPathOfCert(testSuiteConfig.getClient().getKeystorePathValidCerts());
  }

  protected Path getPathOfAlternativeCertificate() {
    return getPathOfCert(testSuiteConfig.getClient().getKeystorePathAlternativeCerts());
  }

  private Path getPathOfCert(final String keystoreValidCertsPath) {
    final Path certPath =
        CertificateProvider.getFilesFromDir(
                PkitsTestSuiteUtils.buildAbsolutePath(keystoreValidCertsPath).toString())
            .sorted()
            .findFirst()
            .orElseThrow();
    log.info("Certificate path: {}", certPath);
    return certPath;
  }

  private Optional<Integer> checkOcspHistory(
      @NonNull final BigInteger certSerialNr,
      final TslSequenceNr tslSequenceNr,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {
    return OcspHistory.check(
        ocspRespUri,
        certSerialNr,
        tslSequenceNr,
        testSuiteConfig.getTestObject().getOcspProcessingTimeSeconds(),
        ocspRequestExpectationBehaviour);
  }

  protected static X509Certificate getDefaultTslSignerCert() {
    return CertReader.getX509FromP12(defaultTslSigner, tslSignerKeystorePassw);
  }

  protected static P12Container getDefaultTslSignerP12() {
    return P12Reader.getContentFromP12(defaultTslSigner, tslSignerKeystorePassw);
  }

  protected static P12Container getTslSignerP12(final Path tslSignerPath) {
    return P12Reader.getContentFromP12(tslSignerPath, tslSignerKeystorePassw);
  }

  private static Optional<Integer> getSutServerPortFromEnvironment() {
    final String systemEnvServerPort = System.getProperty("SUT_SERVER_PORT");
    if (systemEnvServerPort == null || systemEnvServerPort.isEmpty()) {
      return Optional.empty();
    } else {
      return Optional.of(Integer.parseUnsignedInt(systemEnvServerPort));
    }
  }

  protected int getTslDownloadIntervalWithExtraTimeSeconds() {
    return testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds() + 5;
  }

  protected void retrieveCurrentTslSeqNrInTestObject() {

    final int tslDownloadIntervalSeconds = getTslDownloadIntervalWithExtraTimeSeconds();
    log.info("Waiting at most {} seconds for TSL download.", tslDownloadIntervalSeconds);
    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for tslSeqNr " + IGNORE_SEQUENCE_NUMBER,
        tslDownloadIntervalSeconds,
        TslDownload.tslDownloadHistoryHasSpecificEntry(
            tslProvUri, IGNORE_SEQUENCE_NUMBER, TslDownloadEndpointType.XML_ENDPOINTS));
    log.info("Retrieve last known tslSeqNr in history");
    final Integer tslSeqNrOfLastTslDownload =
        TslDownload.getTslSeqNrOfLastTslDownloadRequest(tslProvUri, IGNORE_SEQUENCE_NUMBER);

    if (tslSeqNrOfLastTslDownload == null) {
      throw new TestSuiteException("cannot retrieve last TSL download (or hash) tslSeqNr");
    }

    log.info("Update current tslSeqNr: {}", tslSeqNrOfLastTslDownload);
    tslSequenceNr.saveCurrentTestObjectTslSeqNr(tslSeqNrOfLastTslDownload);
    log.info("Current tslSeqNr in test object is: {}", tslSequenceNr.getCurrentNrInTestObject());
    log.info("tslSequenceNr: {}", tslSequenceNr);
  }
}
