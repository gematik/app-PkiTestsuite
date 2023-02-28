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

package de.gematik.pki.pkits.testsuite.approval;

import static de.gematik.pki.pkits.common.PkitsCommonUtils.waitSeconds;
import static de.gematik.pki.pkits.common.PkitsConstants.GEMATIK_TEST_TSP;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType.OCSP_RESP_TYPE_DEFAULT_USECASE;
import static de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult.USECASE_VALID;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.SIGNER_VALIDITY_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_DO_NOT_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_EXPECT;
import static de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour.OCSP_REQUEST_IGNORE;
import static de.gematik.pki.pkits.testsuite.common.tsl.TslDownload.tslDownloadHistoryHasSpecificEntry;
import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.testsuite.UseCase;
import de.gematik.pki.pkits.testsuite.approval.support.OcspResponderType;
import de.gematik.pki.pkits.testsuite.approval.support.PcapHelper;
import de.gematik.pki.pkits.testsuite.approval.support.PcapManager;
import de.gematik.pki.pkits.testsuite.approval.support.TestResultLoggerExtension;
import de.gematik.pki.pkits.testsuite.approval.support.UseCaseResult;
import de.gematik.pki.pkits.testsuite.common.CertificateProvider;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory.OcspRequestExpectationBehaviour;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspResponderInstance;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.TslGeneration;
import de.gematik.pki.pkits.testsuite.common.tsl.TslModification;
import de.gematik.pki.pkits.testsuite.common.tsl.TslProviderInstance;
import de.gematik.pki.pkits.testsuite.common.tsl.TslSequenceNr;
import de.gematik.pki.pkits.testsuite.config.Afo;
import de.gematik.pki.pkits.testsuite.config.OcspSettings;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.config.TslSettings;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.awaitility.core.ConditionTimeoutException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.w3c.dom.Document;

@Slf4j
@DisplayName("Base class for all PKI approval tests.")
@TestMethodOrder(OrderAnnotation.class)
@ExtendWith(TestResultLoggerExtension.class)
class ApprovalTestsBaseIT {

  protected static final String TSL_TEMPLATES_DIRNAME = "../testDataTemplates/tsl/";
  protected static final String TRUST_ANCHOR_TEMPLATES_DIRNAME =
      "../testDataTemplates/certificates/ecc/trustAnchor/";
  protected static String clientKeystorePassw;
  protected static String ocspRespUri;
  protected static String tslProvUri;
  protected static OcspSettings ocspSettings;
  protected static TslSettings tslSettings;

  protected static Path tslSigner;
  protected static String tslSignerKeystorePassw;

  protected static P12Container ocspSigner;
  private static final int TSL_DAYS_UNTIL_NEXTUPDATE = 90;
  protected static final TestSuiteConfig testSuiteConfig = TestConfigManager.getTestSuiteConfig();
  private static final int WEB_SERVER_START_TIMEOUT_SECS = 30;
  protected static TslSequenceNr tslSequenceNr;

  private PcapManager pcapManager = null;

  protected TestInfo currentTestInfo;

  protected static final Map<String, Function<TestSuiteConfig, Integer>> timeoutAndDelayFuncMap =
      Map.of(
          "shortDelay",
          (_testSuiteConfig) ->
              _testSuiteConfig.getTestObject().getOcspTimeoutSeconds() * 1000
                  - _testSuiteConfig
                      .getTestSuiteParameter()
                      .getOcspSettings()
                      .getTimeoutDeltaMilliseconds(),
          "longDelay",
          (_testSuiteConfig) ->
              _testSuiteConfig.getTestObject().getOcspTimeoutSeconds() * 1000
                  + _testSuiteConfig
                      .getTestSuiteParameter()
                      .getOcspSettings()
                      .getTimeoutDeltaMilliseconds());

  protected String getTestInfoStr() {

    final Method method = currentTestInfo.getTestMethod().orElseThrow();
    return "%s.%s\n%s"
        .formatted(
            method.getDeclaringClass().getSimpleName(),
            method.getName(),
            currentTestInfo.getDisplayName());
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
    tslSigner = tslSettings.getSigner();
    tslSignerKeystorePassw = tslSettings.getSignerPassword();

    ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(TestSuiteConstants.OCSP_SIGNER_FILENAME),
            ocspSettings.getSignerPassword());

    log.info(
        "TestObject: {}:{}", testSuiteConfig.getTestObject().getIpAddressOrFqdn(), sutServerPort);

    if (testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic()) {
      PcapHelper.assignDevices(testSuiteConfig);
    }
  }

  @BeforeEach
  void setupBeforeEach(final TestInfo testInfo) {
    currentTestInfo = testInfo;
    if (testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic()) {
      pcapManager =
          new PcapManager(
              PcapHelper.pcapService,
              PcapHelper.pcapDeviceCommonInfos,
              "../out/logs/",
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
        getTestInfoStr());

    if (testSuiteConfig.getTestSuiteParameter().isCaptureNetworkTraffic()
        || (pcapManager != null)) {
      pcapManager.stop();
      pcapManager.close();
      pcapManager.createGzipFile();
      pcapManager.deletePcapFile();
      pcapManager = null;
    }
  }

  @AfterAll
  static void tearDownAfterAll() {
    OcspResponderInstance.getInstance().stopServer();
    TslProviderInstance.getInstance().stopServer();
    log.debug("ApprovalTest(s) finished.");
  }

  protected void testCaseMessage(@NonNull final TestInfo testInfo) {
    log.info(
        """

            =======================================================================================
            =======================================================================================
            Starting test case: {}
            =======================================================================================

            """,
        getTestInfoStr());

    Arrays.stream(testInfo.getTestMethod().orElseThrow().getAnnotationsByType(Afo.class))
        .toList()
        .forEach(afo -> log.info("{} - {}", afo.afoId(), afo.description()));
  }

  protected void initialState() throws DatatypeConfigurationException, IOException {
    if (testSuiteConfig.getTestSuiteParameter().isPerformInitialState()) {
      log.info("\n\n===> Establishing initial state... - {}\n", getTestInfoStr());
      if (tslSettings.isInitialStateTslImport()) {
        initialTslDownloadByTestObject();
      } else {
        // tslSequenceNr.setExpectedNrInTestObject(tslSequenceNr.getCurrentNrInTestObject());
        log.info(
            "\n===> Initial state TSL import skipped by user request. - {}\n", getTestInfoStr());
      }
      useCaseWithCert(
          true,
          getPathOfFirstValidCert(),
          USECASE_VALID,
          OCSP_RESP_TYPE_DEFAULT_USECASE,
          OCSP_REQUEST_EXPECT);
      log.info("\n\n===> Initial state successful! - {}\n\n", getTestInfoStr());
    } else {
      log.info("\n\n===> Initial state use case skipped by user request. - {}\n", getTestInfoStr());
    }
  }

  void bringInTslDownload(
      final Path tslTemplate,
      final Path tslSignerP12Path,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour,
      final Path useCaseCertPath,
      final UseCaseResult useCaseResult)
      throws DatatypeConfigurationException, IOException {
    bringInTslDownload(
        tslTemplate,
        tslSignerP12Path,
        ocspRequestExpectationBehaviour,
        useCaseCertPath,
        useCaseResult,
        null);
  }

  void bringInTslDownload(
      final Path tslTemplate,
      final Path tslSignerP12Path,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour,
      final Path useCaseCertPath,
      final UseCaseResult useCaseResult,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviourForUseCase)
      throws DatatypeConfigurationException, IOException {

    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);

    final TslDownload tslDownload =
        getTslDownloadWithTemplateAndSigner(
            offeredSeqNr,
            tslTemplate,
            tslSignerP12Path,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    tslDownload.configureOcspResponderTslSignerStatusGood();
    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitForTslDownload(tslSequenceNr.getExpectedNrInTestObject());

    if (ocspRequestExpectationBehaviour == OCSP_REQUEST_EXPECT) {
      tslDownload.waitUntilOcspRequestForSigner();
      tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);
    } else if (ocspRequestExpectationBehaviour == OCSP_REQUEST_IGNORE) {
      tslDownload.waitUntilOcspRequestForSignerOptional();
    } else {
      throw new TestSuiteException("not implemented");
    }

    if (useCaseResult == null) {
      return;
    }

    final OcspRequestExpectationBehaviour ocspRequestExpectation;
    if (useCaseResult == USECASE_VALID) {
      ocspRequestExpectation =
          ObjectUtils.defaultIfNull(ocspRequestExpectationBehaviourForUseCase, OCSP_REQUEST_EXPECT);
    } else {
      ocspRequestExpectation =
          ObjectUtils.defaultIfNull(
              ocspRequestExpectationBehaviourForUseCase, OCSP_REQUEST_DO_NOT_EXPECT);
    }

    useCaseWithCert(
        useCaseCertPath, useCaseResult, OCSP_RESP_TYPE_DEFAULT_USECASE, ocspRequestExpectation);
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
          "Start useCaseWithCert for {} with parameters\n  {}\n  {}\n  {}\n  {}\n\n",
          getTestInfoStr(),
          certPath,
          useCaseResult,
          ocspResponderType,
          ocspRequestExpectationBehaviour);
    }

    if (ocspResponderType == OCSP_RESP_TYPE_DEFAULT_USECASE) {
      TestEnvironment.configureOcspResponder(
          ocspRespUri,
          OcspResponderConfigDto.builder()
              .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
              .signer(ocspSigner)
              .build());
    }

    waitForOcspCacheToExpire();

    final String message =
        "\"%s\" in useCaseWithCert for %s with parameters\n  %s\n  %s\n  %s\n\n"
            .formatted(
                useCaseResult.getMessage(),
                getTestInfoStr(),
                useCaseResult,
                ocspResponderType,
                ocspRequestExpectationBehaviour);

    assertThat(UseCase.exec(certPath)).as(message).isEqualTo(useCaseResult.getExpectedReturnCode());
    // mje 14.2. tslSequenceNr.saveCurrentTestObjectSeqNr(tslSequenceNr.getLastOfferedNr());

    if (ocspRequestExpectationBehaviour != OCSP_REQUEST_IGNORE) {
      log.info("{}", tslSequenceNr);
      checkOcspHistory(
          CertReader.getX509FromP12(certPath, clientKeystorePassw).getSerialNumber(),
          tslSequenceNr,
          ocspRequestExpectationBehaviour);
    }
    if (!isInitialState) {
      log.info(
          """
              Successfully completed useCaseWithCert for {} with parameters
                {}
                {}
                {}
                {}

              """,
          getTestInfoStr(),
          certPath,
          useCaseResult,
          ocspResponderType,
          ocspRequestExpectationBehaviour);
    }
    log.info("{}", tslSequenceNr);
  }

  protected void assertNoOcspRequest(final TslDownload tslDownload) {
    final String expectedMessage1 =
        "Timeout for event \"OcspRequestHistoryHasEntry for TSL signer cert %s\""
            .formatted(tslDownload.getTslSignerCert().getSerialNumber());

    assertThatThrownBy(tslDownload::waitUntilOcspRequestForSigner)
        .isInstanceOf(TestSuiteException.class)
        .hasMessage(expectedMessage1)
        .cause()
        .isInstanceOf(ConditionTimeoutException.class)
        .hasMessage(
            "Condition with de.gematik.pki.pkits.testsuite.common.tsl.TslDownload was not fulfilled within %s seconds."
                .formatted(testSuiteConfig.getTestObject().getTslProcessingTimeSeconds()));

    log.info("As expected, observed an TestSuiteException with message <{}>", expectedMessage1);
  }

  protected void waitForOcspCacheToExpire() {
    final int seconds = testSuiteConfig.getTestObject().getOcspGracePeriodSeconds();
    waitForOcspCacheToExpire(seconds);
  }

  protected void waitForOcspCacheToExpire(int seconds) {
    seconds = seconds + ocspSettings.getGracePeriodExtraDelay();
    log.info("Waiting {} seconds for ocsp cache to expire.", seconds);
    waitSeconds(seconds);
  }

  protected Path getPathOfFirstValidCert() {
    final String keystoreValidCertsPath =
        TestConfigManager.getTestSuiteConfig().getClient().getKeystorePathValidCerts();

    final Path certPath =
        CertificateProvider.getFilesFromDir(
                PkitsTestSuiteUtils.buildAbsolutePath(keystoreValidCertsPath).toString())
            .findFirst()
            .orElseThrow();
    log.info("Certificate path: {}", certPath);
    return certPath;
  }

  protected Path getPathOfAlternativeCertificate() {
    final String keystoreValidCertsPath =
        TestConfigManager.getTestSuiteConfig().getClient().getKeystorePathAlternativeCerts();

    final Path certPath =
        CertificateProvider.getFilesFromDir(
                PkitsTestSuiteUtils.buildAbsolutePath(keystoreValidCertsPath).toString())
            .findFirst()
            .orElseThrow();
    log.info("Certificate path: {}", certPath);
    return certPath;
  }

  private void checkOcspHistory(
      @NonNull final BigInteger certSerialNr,
      final TslSequenceNr tslSequenceNr,
      final OcspRequestExpectationBehaviour ocspRequestExpectationBehaviour) {
    OcspHistory.check(ocspRespUri, certSerialNr, tslSequenceNr, ocspRequestExpectationBehaviour);
  }

  static TslDownload getTslDownloadDefaultTemplate(final int offeredSeqNr)
      throws DatatypeConfigurationException, IOException {
    return getTslDownloadWithTemplate(offeredSeqNr, tslSettings.getDefaultTemplate());
  }

  static TslDownload getTslDownloadAlternativeTemplate(final int offeredSeqNr)
      throws DatatypeConfigurationException, IOException {
    return getTslDownloadWithTemplate(offeredSeqNr, tslSettings.getAlternativeTemplate());
  }

  protected static final String TSL_DIRNAME = "../out/tsl";
  protected static final String TSL_FILENAME_PREFIX = "Tsl_";

  protected static Path getTslOutputPath(final BigInteger tslSeqNr, final String tslId) {
    return Path.of(TSL_DIRNAME, "%s%04d_%s.xml".formatted(TSL_FILENAME_PREFIX, tslSeqNr, tslId));
  }

  static TslDownload getTslDownloadWithTemplate(final int offeredSeqNr, final Path template)
      throws DatatypeConfigurationException, IOException {
    return getTslDownloadWithTemplateAndSigner(
        offeredSeqNr,
        template,
        tslSigner,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);
  }

  static TslDownload getTslDownloadWithTemplateAndSigner(
      final int offeredSeqNr,
      final Path tslTemplate,
      final Path tslSignerP12Path,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck)
      throws DatatypeConfigurationException, IOException {

    final P12Container tslSignerP12 =
        P12Reader.getContentFromP12(
            GemLibPkiUtils.readContent(tslSignerP12Path), tslSignerKeystorePassw);
    final X509Certificate tslSignerCert = tslSignerP12.getCertificate();

    final byte[] tslBytes =
        createTslForTestObject(
            tslTemplate,
            tslSignerP12Path,
            tslSignerKeystorePassw,
            offeredSeqNr,
            signerKeyUsageCheck,
            signerValidityCheck);

    final TslDownload tslDownload =
        TslDownload.builder()
            .tslBytes(tslBytes)
            .tslDownloadIntervalSeconds(
                testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds() + 5)
            .tslProcessingTimeSeconds(testSuiteConfig.getTestObject().getTslProcessingTimeSeconds())
            .tslProvUri(tslProvUri)
            .ocspRespUri(ocspRespUri)
            .tslDownloadPoint(TSL_DOWNLOAD_POINT_PRIMARY)
            .tslSignerCert(tslSignerCert)
            .build();

    writeTsl(tslDownload, "");

    return tslDownload;
  }

  protected void signAndSetTslBytes(
      final TslDownload tslDownload, @NonNull final Path tslSignerPath, final byte[] tslBytes) {

    final Document tslDoc = TslConverter.bytesToDoc(tslBytes);

    final byte[] tslBytesSigned =
        TslGeneration.signTslDoc(
            tslDoc,
            tslSignerPath,
            tslSignerKeystorePassw,
            SIGNER_KEY_USAGE_CHECK_ENABLED,
            SIGNER_VALIDITY_CHECK_ENABLED);

    tslDownload.setTslBytes(tslBytesSigned);
  }

  protected static void writeTsl(final TslDownload tslDownload, final String postfix)
      throws IOException {

    final Path tslOutputPath =
        getTslOutputPath(
            TslReader.getSequenceNumber(tslDownload.getTsl()),
            tslDownload.getTsl().getId() + postfix);
    if (!Files.exists(tslOutputPath.getParent())) {
      Files.createDirectories(tslOutputPath.getParent());
      Files.createFile(tslOutputPath);
    }
    Files.write(tslOutputPath, tslDownload.getTslBytes());
  }

  protected static TslDownload initialTslDownloadByTestObject()
      throws DatatypeConfigurationException, IOException {
    final int offeredSeqNr = tslSequenceNr.getNextTslSeqNr();

    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload = getTslDownloadDefaultTemplate(offeredSeqNr);

    tslSequenceNr.setLastOfferedNr(offeredSeqNr);
    tslDownload.waitUntilTslDownloadCompleted(IGNORE_SEQUENCE_NUMBER);
    tslSequenceNr.setExpectedNrInTestObject(offeredSeqNr);
    log.info("Finished initial TSL download: seqNr {}.", offeredSeqNr);

    return tslDownload;
  }

  protected static X509Certificate getDefaultTslSignerCert() {
    return CertReader.getX509FromP12(tslSigner, tslSignerKeystorePassw);
  }

  protected static byte[] createTslForTestObject(
      @NonNull final Path tslTemplate,
      final Path tslSinger,
      final String tslSingerPassw,
      final int seqNr,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck)
      throws DatatypeConfigurationException {

    final TslModification tslModification = getTslModification(seqNr);
    return TslGeneration.createTslFromFile(
        tslTemplate,
        tslModification,
        tslSinger,
        tslSingerPassw,
        signerKeyUsageCheck,
        signerValidityCheck);
  }

  private static String getTslDownloadUrlPrimary(final int seqNr) {
    return tslProvUri + TSL_XML_PRIMARY_ENDPOINT + "?" + TSL_SEQNR_PARAM_ENDPOINT + "=" + seqNr;
  }

  private static String getTslDownloadUrlBackup(final int seqNr) {
    return tslProvUri + TSL_XML_BACKUP_ENDPOINT + "?" + TSL_SEQNR_PARAM_ENDPOINT + "=" + seqNr;
  }

  private static TslModification getTslModification(final int seqNr) {
    return TslModification.builder()
        .sequenceNr(seqNr)
        .tspName(GEMATIK_TEST_TSP)
        .newSsp(ocspRespUri + OCSP_SSP_ENDPOINT + "/" + seqNr)
        .tslDownloadUrlPrimary(getTslDownloadUrlPrimary(seqNr))
        .tslDownloadUrlBackup(getTslDownloadUrlBackup(seqNr))
        .issueDate(ZonedDateTime.now(ZoneOffset.UTC))
        .nextUpdate(null)
        .daysUntilNextUpdate(TSL_DAYS_UNTIL_NEXTUPDATE)
        .build();
  }

  private static Optional<Integer> getSutServerPortFromEnvironment() {
    final String systemEnvServerPort = System.getProperty("SUT_SERVER_PORT");
    if (systemEnvServerPort == null || systemEnvServerPort.isEmpty()) {
      return Optional.empty();
    } else {
      return Optional.of(Integer.parseUnsignedInt(systemEnvServerPort));
    }
  }

  private void retrieveCurrentTslSeqNrInTestObject() {

    final int tslDownloadIntervalSeconds =
        testSuiteConfig.getTestObject().getTslDownloadIntervalSeconds() + 5;
    log.info("Waiting at most {} seconds for tsl download.", tslDownloadIntervalSeconds);
    PkitsTestSuiteUtils.waitForEvent(
        "TslDownloadHistoryHasEntry for seqNr " + IGNORE_SEQUENCE_NUMBER,
        tslDownloadIntervalSeconds,
        tslDownloadHistoryHasSpecificEntry(tslProvUri, IGNORE_SEQUENCE_NUMBER));
    log.info("Retrieve last know TSL seqNr in history");
    final Integer seqNrOfLastTslDownload =
        TslDownload.getSeqNrOfLastTslDownload(tslProvUri, IGNORE_SEQUENCE_NUMBER);

    if (seqNrOfLastTslDownload == null) {
      throw new TestSuiteException("cannot retrieve last TSL download (or hash) seqNr");
    }

    log.info("Update current TSL seqNr: {}", seqNrOfLastTslDownload);
    tslSequenceNr.saveCurrentTestObjectSeqNr(seqNrOfLastTslDownload);
    log.info("Current TSL seqNr in test object is: {}", tslSequenceNr.getCurrentNrInTestObject());
  }

  @Test
  @Order(1)
  @DisplayName("Check initial state")
  void checkInitialState(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    retrieveCurrentTslSeqNrInTestObject();
    initialState();
  }
}
