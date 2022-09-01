/*
 * Copyright (c) 2022 gematik GmbH
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
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestIT.OcspResponderType.OCSP_RESP_TYPE_CUSTOM;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestIT.OcspResponderType.OCSP_RESP_TYPE_DEFAULT;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestIT.UseCaseResult.EXPECT_FAILURE;
import static de.gematik.pki.pkits.testsuite.approval.ApprovalTestIT.UseCaseResult.EXPECT_PASS;
import static de.gematik.pki.pkits.testsuite.common.TestsuiteConstants.PKITS_CERT.PKITS_CERT_INVALID;
import static de.gematik.pki.pkits.testsuite.common.TestsuiteConstants.PKITS_CERT.PKITS_CERT_VALID;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto;
import de.gematik.pki.pkits.ocsp.responder.data.OcspResponderConfigDto.CustomCertificateStatusDto;
import de.gematik.pki.pkits.testsuite.UseCase;
import de.gematik.pki.pkits.testsuite.common.CertificateProvider;
import de.gematik.pki.pkits.testsuite.common.PkitsTestsuiteUtils;
import de.gematik.pki.pkits.testsuite.common.TestsuiteConstants;
import de.gematik.pki.pkits.testsuite.common.VariableSource;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspHistory;
import de.gematik.pki.pkits.testsuite.common.ocsp.OcspResponderInstance;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.TslGeneration;
import de.gematik.pki.pkits.testsuite.common.tsl.TslModification;
import de.gematik.pki.pkits.testsuite.common.tsl.TslProviderInstance;
import de.gematik.pki.pkits.testsuite.common.tsl.TslSequenceNr;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestEnvironment;
import de.gematik.pki.pkits.testsuite.config.TestsuiteConfig;
import de.gematik.pki.pkits.testsuite.config.TestsuiteParameter.OcspSettings;
import de.gematik.pki.pkits.testsuite.config.TestsuiteParameter.TslSettings;
import de.gematik.pki.pkits.tsl.provider.data.TslRequestHistoryEntryDto;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

@Slf4j
@DisplayName("PKI approval tests.")
@TestMethodOrder(OrderAnnotation.class)
class ApprovalTestIT {

  private static String clientKeystorePassw;
  private static String ocspRespUri;
  private static String tslProvUri;
  private static OcspSettings ocspSettings;
  private static TslSettings tslSettings;

  private static P12Container ocspSigner;
  private static final int TSL_DAYS_UNTIL_NEXTUPDATE = 90;
  private static final TestsuiteConfig testsuiteConfig = TestConfigManager.getTestsuiteConfig();
  private static final int WEB_SERVER_START_TIMEOUT_SECS = 30;
  private static TslSequenceNr tslSequenceNr;

  enum UseCaseResult {
    EXPECT_PASS,
    EXPECT_FAILURE
  }

  enum OcspResponderType {
    OCSP_RESP_TYPE_DEFAULT,
    OCSP_RESP_TYPE_CUSTOM
  }

  @BeforeAll
  static void setup() {
    log.debug("ApprovalTest(s) started.");
    tslSequenceNr = TslSequenceNr.getInstance();

    final int sutServerPort =
        getSutServerPortFromEnvironment().orElse((testsuiteConfig.getTestObject().getPort()));
    testsuiteConfig.getTestObject().setPort(sutServerPort);
    clientKeystorePassw = testsuiteConfig.getClient().getKeystorePassword();

    OcspResponderInstance.getInstance().startServer();
    TslProviderInstance.getInstance().startServer();

    ocspRespUri =
        OcspResponderInstance.getInstance().waitUntilWebServerIsUp(WEB_SERVER_START_TIMEOUT_SECS);
    log.info("OcspResponderInstance: {}", ocspRespUri);
    tslProvUri =
        TslProviderInstance.getInstance().waitUntilWebServerIsUp(WEB_SERVER_START_TIMEOUT_SECS);
    log.info("TslProviderInstance: {}", tslProvUri);
    ocspSettings = testsuiteConfig.getTestsuiteParameter().getOcspSettings();
    tslSettings = testsuiteConfig.getTestsuiteParameter().getTslSettings();

    ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(TestsuiteConstants.OCSP_SIGNER_FILENAME),
            ocspSettings.getSignerPassword());

    log.info("Testobject: {}:{}", testsuiteConfig.getTestObject().getIpAddress(), sutServerPort);
    log.info("Ocsp requests expected: {}", ocspSettings.isRequestsExpected());
  }

  private static void initialTslDownloadByTestobject()
      throws DatatypeConfigurationException, IOException {
    final int offeredSeqNr = tslSequenceNr.getCurrentNrInTestobject() + 1;
    log.info("Offering TSL with seqNr. {} for download.", offeredSeqNr);
    final TslDownload tslDownload =
        TslDownload.builder()
            .tslBytes(
                createTslForTestobject(
                    testsuiteConfig.getTestsuiteParameter().getTslSettings(), offeredSeqNr))
            .tslDownloadTimeoutSecs(tslSettings.getDownloadIntervalSeconds() + 5)
            .tslProcessingTimeSeconds(testsuiteConfig.getTestObject().getTslProcessingTimeSeconds())
            .tslProvUri(tslProvUri)
            .ocspRespUri(ocspRespUri)
            .ocspRequestExpected(
                testsuiteConfig.getTestsuiteParameter().getOcspSettings().isRequestsExpected())
            .tslDownloadPoint(TSL_DOWNLOAD_POINT_PRIMARY)
            .tslSignerCert(readTslSignerCert())
            .build();
    Files.write(
        Path.of("target/generatedTslSeqNr_" + offeredSeqNr + ".xml"), tslDownload.getTslBytes());
    TestEnvironment.clearOspResponderHistory(ocspRespUri);
    TestEnvironment.clearTslProviderHistory(tslProvUri);

    tslDownload.waitUntilTslDownloadCompleted();

    tslSequenceNr.setExpectedNrInTestobject(offeredSeqNr);
    tslSequenceNr.updateCurrentNrInTestobject(offeredSeqNr);
    TestEnvironment.clearOspResponderHistory(ocspRespUri);
    TestEnvironment.clearTslProviderHistory(tslProvUri);
  }

  private static byte[] createTslForTestobject(@NonNull final TslSettings tslCfg, final int seqNr)
      throws DatatypeConfigurationException {
    final TslModification tslMod = getTslModification(seqNr);
    return TslGeneration.createTslFromFile(
        tslCfg.getDefaultTemplate(), tslMod, tslCfg.getSigner(), tslCfg.getSignerPassword());
  }

  private static TslModification getTslModification(final int seqNr) {
    return TslModification.builder()
        .sequenceNr(seqNr)
        .tspName(GEMATIK_TEST_TSP)
        .newSsp(ocspRespUri + OCSP_SSP_ENDPOINT + "/" + seqNr)
        .tslDownloadUrlPrimary(
            tslProvUri + TSL_XML_ENDPOINT + "?" + TSL_SEQNR_PARAM_ENDPOINT + "=" + seqNr)
        .tslDownloadUrlBackup(
            tslProvUri + TSL_XML_BACKUP_ENDPOINT + "?" + TSL_SEQNR_PARAM_ENDPOINT + "=" + seqNr)
        .issueDate(ZonedDateTime.now(ZoneOffset.UTC))
        .nextUpdate(null)
        .daysUntilNextUpdate(TSL_DAYS_UNTIL_NEXTUPDATE)
        .build();
  }

  private static X509Certificate readTslSignerCert() {
    return CertReader.getX509FromP12(tslSettings.getSigner(), tslSettings.getSignerPassword());
  }

  private static int getSeqNrOfLastTslRequestHistoryEntry(
      final List<TslRequestHistoryEntryDto> history) {
    return history.get(history.size() - 1).getSequenceNr();
  }

  private static Optional<Integer> getSutServerPortFromEnvironment() {
    final String systemEnvServerPort = System.getProperty("SUT_SERVER_PORT");
    if (systemEnvServerPort == null || systemEnvServerPort.isEmpty()) {
      return Optional.empty();
    } else {
      return Optional.of(Integer.parseUnsignedInt(systemEnvServerPort));
    }
  }

  @AfterAll
  static void tearDown() {
    OcspResponderInstance.getInstance().stopServer();
    TslProviderInstance.getInstance().stopServer();
    log.debug("ApprovalTest(s) finished.");
  }

  @Test
  @Order(1)
  @DisplayName("Check initial state")
  void checkInitialState() throws DatatypeConfigurationException, IOException {
    log.info("\n===> Establishing initial state...");
    initialState();
    log.info("\n===> Initial state successful");
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_VALID)
  @DisplayName("Test use case with valid certificates")
  void verifyConnectCertsValid(final Path certPath, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {
    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT);
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = PKITS_CERT_INVALID)
  @DisplayName("Test use case with invalid certificates")
  void verifyConnectCertsInvalid(final Path certPath)
      throws DatatypeConfigurationException, IOException {

    log.info("\nCertificate path: {}\n", certPath);
    initialState();
    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_DEFAULT);

    // TODO: ee_invalid-extension-crit.p12 does not throw...?

  }

  @Test
  @DisplayName("Test missing CertHash in OCSP Response")
  void verifyMissingCertHashInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();
    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .withCertHash(false)
            .build());

    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test invalid CertHash in OCSP Response")
  void verifyInvalidCertHashInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    final Path certPath = getPathOfFirstValidCert();

    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .validCertHash(false)
            .build());

    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test invalid signature in OCSP Response")
  void verifyInvalidSignatureInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();
    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .validSignature(false)
            .build());

    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
  }

  @ParameterizedTest
  @DisplayName("Test missing OCSP signer in TSL")
  @ValueSource(
      strings = {
        TestsuiteConstants.OCSP_SIGNER_NOT_IN_TSL_FILENAME,
        TestsuiteConstants.OCSP_SIGNER_DIFFERENT_KEY
      })
  void verifyMissingOcspSignerInTsl(final String signerFilename, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    final P12Container signer =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(signerFilename),
            ocspSettings.getSignerPassword());

    final Path certPath = getPathOfFirstValidCert();

    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(signer)
            .build());

    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test invalid cert Id in OCSP Response")
  void verifyInvalidCerIdInOcspResponse(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();
    TestEnvironment.configureOcspResponder(
        ocspRespUri,
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .validCertId(false)
            .build());

    waitForOcspCacheToExpire();
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test OCSP grace period")
  void verifyOcspGracePeriod(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dtoGood =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .build();

    final OcspResponderConfigDto dtoUnknown =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .build();

    waitForOcspCacheToExpire();
    TestEnvironment.configureOcspResponder(ocspRespUri, dtoUnknown);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoGood);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test OCSP certificate status revoked and unknown")
  void verifyOcspCertificateStatusRevokedAndUnknown(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dtoGood =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .build();

    final OcspResponderConfigDto dtoUnknown =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .certificateStatus(CustomCertificateStatusDto.createUnknown())
            .build();

    final OcspResponderConfigDto dtoRevoked =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .certificateStatus(
                CustomCertificateStatusDto.createRevoked(
                    ZonedDateTime.now(), CRLReason.aACompromise))
            .build();

    waitForOcspCacheToExpire();
    TestEnvironment.configureOcspResponder(ocspRespUri, dtoUnknown);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);

    waitForOcspCacheToExpire();
    TestEnvironment.configureOcspResponder(ocspRespUri, dtoRevoked);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);

    waitForOcspCacheToExpire();
    TestEnvironment.configureOcspResponder(ocspRespUri, dtoGood);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM);
  }

  @ParameterizedTest
  @EnumSource(
      value = OCSPRespStatus.class,
      names = {"INTERNAL_ERROR", "MALFORMED_REQUEST", "TRY_LATER", "UNAUTHORIZED"})
  @DisplayName("Test various status of OCSP response and response bytes being null or not null")
  void verifyOcspResponseVariousStatusAndResponseBytes(
      final OCSPRespStatus ocspRespStatus, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final Path certPath = getPathOfFirstValidCert();

    log.info("Test with ocsp status: {}", ocspRespStatus);
    for (final boolean withResponseBytes : List.of(true, false)) {
      log.info("Test with response bytes: {}", withResponseBytes);
      final OcspResponderConfigDto dto =
          OcspResponderConfigDto.builder()
              .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
              .signer(ocspSigner)
              .respStatus(ocspRespStatus)
              .withResponseBytes(withResponseBytes)
              .build();
      waitForOcspCacheToExpire();
      TestEnvironment.configureOcspResponder(ocspRespUri, dto);
      useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
    }
  }

  @Test
  @DisplayName("Test OCSP Response with timeout and delay")
  void verifyOcspResponseTimeoutAndDelay(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dtoShortDelay =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .delayMilliseconds(
                testsuiteConfig.getTestObject().getOcspTimeoutSeconds() * 1000
                    - ocspSettings.getTimeoutDeltaMilliseconds())
            .build();

    final OcspResponderConfigDto dtoLongDelay =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .delayMilliseconds(
                testsuiteConfig.getTestObject().getOcspTimeoutSeconds() * 1000
                    + ocspSettings.getTimeoutDeltaMilliseconds())
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoShortDelay);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM);
    waitForOcspCacheToExpire();

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoLongDelay);
    useCaseWithCert(certPath, EXPECT_FAILURE, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test OCSP Response with responder id byName")
  void verifyOcspResponseResponderIdByName(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .responderIdType(ResponderIdType.BY_NAME)
            .build();

    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM);
  }

  private enum DtoDateConfigOption {
    THIS_UPDATE,
    PRODUCED_AT,
    NEXT_UPDATE
  }

  private void verifyOcspResponseDate(
      final DtoDateConfigOption dateConfigOption,
      final int deltaMilliseconds,
      final UseCaseResult validUseCase) {

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto.OcspResponderConfigDtoBuilder dtoBuilder =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner);

    switch (dateConfigOption) {
      case THIS_UPDATE -> dtoBuilder.thisUpdateDeltaMilliseconds(deltaMilliseconds);
      case PRODUCED_AT -> dtoBuilder.producedAtDeltaMilliseconds(deltaMilliseconds);
      case NEXT_UPDATE -> dtoBuilder.nextUpdateDeltaMilliseconds(deltaMilliseconds);
    }

    TestEnvironment.configureOcspResponder(ocspRespUri, dtoBuilder.build());
    useCaseWithCert(certPath, validUseCase, OCSP_RESP_TYPE_CUSTOM);
  }

  @Test
  @DisplayName("Test OCSP Response thisUpdate future out of tolerance")
  void verifyOcspResponseThisUpdateFutureOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds, EXPECT_FAILURE);
    waitForOcspCacheToExpire(
        ocspSettings.getGracePeriodSeconds() + thisUpdateDeltaMilliseconds / 1000);
  }

  @Test
  @DisplayName("Test OCSP Response thisUpdate future within tolerance")
  void verifyOcspResponseThisUpdateFutureWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int thisUpdateDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.THIS_UPDATE, thisUpdateDeltaMilliseconds, EXPECT_PASS);
    waitForOcspCacheToExpire(
        ocspSettings.getGracePeriodSeconds() + thisUpdateDeltaMilliseconds / 1000);
  }

  @Test
  @DisplayName("Test OCSP Response producedAt future out of tolerance")
  void verifyOcspResponseProducedAtFutureOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS + ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_FAILURE);
    waitForOcspCacheToExpire(
        ocspSettings.getGracePeriodSeconds() + producedAtDeltaMilliseconds / 1000);
  }

  @Test
  @DisplayName("Test OCSP Response producedAt future within tolerance")
  void verifyOcspResponseProducedAtFutureWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int producedAtDeltaMilliseconds =
        OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS - ocspSettings.getTimeoutDeltaMilliseconds();

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_PASS);
    waitForOcspCacheToExpire(
        ocspSettings.getGracePeriodSeconds() + producedAtDeltaMilliseconds / 1000);
  }

  @Test
  @DisplayName("Test OCSP Response producedAt past out of tolerance")
  void verifyOcspResponseProducedAtPastOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_FAILURE);
  }

  @Test
  @DisplayName("Test OCSP Response producedAt past within tolerance")
  void verifyOcspResponseProducedAtPastWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int producedAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.PRODUCED_AT, producedAtDeltaMilliseconds, EXPECT_PASS);
  }

  @Test
  @DisplayName("Test OCSP Response nextUpdate past out of tolerance")
  void verifyOcspResponseNextUpdatePastOutOfTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int nextUpdateDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            + ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.NEXT_UPDATE, nextUpdateDeltaMilliseconds, EXPECT_FAILURE);
  }

  @Test
  @DisplayName("Test OCSP Response NextUpdate past within tolerance")
  void verifyOcspResponseNextUpdatePastWithinTolerance(final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final int nextUpdateAtDeltaMilliseconds =
        -(OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS
            - ocspSettings.getTimeoutDeltaMilliseconds());

    verifyOcspResponseDate(
        DtoDateConfigOption.NEXT_UPDATE, nextUpdateAtDeltaMilliseconds, EXPECT_PASS);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  @DisplayName("Test OCSP Response with Null Parameter in CertId")
  void verifyOcspResponseWithNullParameterInCertId(
      final boolean withNullParameterHashAlgoOfCertId, final TestInfo testInfo)
      throws DatatypeConfigurationException, IOException {

    testCaseMessage(testInfo);
    initialState();
    waitForOcspCacheToExpire();

    final Path certPath = getPathOfFirstValidCert();

    final OcspResponderConfigDto dto =
        OcspResponderConfigDto.builder()
            .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
            .signer(ocspSigner)
            .withNullParameterHashAlgoOfCertId(withNullParameterHashAlgoOfCertId)
            .build();
    TestEnvironment.configureOcspResponder(ocspRespUri, dto);
    useCaseWithCert(certPath, EXPECT_PASS, OCSP_RESP_TYPE_CUSTOM);
  }

  private void testCaseMessage(@NonNull final TestInfo testInfo) {
    log.info(
        "\n\n\n\n===> Starting test case: {} ({})===\n",
        testInfo.getDisplayName(),
        testInfo.getTestMethod().orElseThrow().getName());
  }

  private void initialState() throws DatatypeConfigurationException, IOException {

    if (testsuiteConfig.getTestsuiteParameter().isInitialStateUseCase()) {
      if (tslSettings.isInitialStateTslImport()) {
        initialTslDownloadByTestobject();
      }
      waitForOcspCacheToExpire();
      useCaseWithCert(getPathOfFirstValidCert(), EXPECT_PASS, OCSP_RESP_TYPE_DEFAULT);
    }
  }

  /**
   * @param certPath Pfad zum genutzten Zertifikat
   * @param validUseCase wird erwartet, dass der UseCase korrekt ausgeführt wird?
   */
  private void useCaseWithCert(
      @NonNull final Path certPath,
      final UseCaseResult validUseCase,
      final OcspResponderType ocspResponderType) {
    TestEnvironment.clearOspResponderHistory(ocspRespUri);
    TestEnvironment.clearTslProviderHistory(tslProvUri);
    // TODO clean OCSPResponder und TSL Responder Config (Defaults? Null? Deactivated?)

    if (ocspResponderType == OCSP_RESP_TYPE_DEFAULT) {
      TestEnvironment.configureOcspResponder(
          ocspRespUri,
          OcspResponderConfigDto.builder()
              .eeCert(CertReader.getX509FromP12(certPath, clientKeystorePassw))
              .signer(ocspSigner)
              .build());
    }

    if (validUseCase == EXPECT_PASS) {
      assertThat(UseCase.exec(certPath)).as("Expecting a valid use case execution.").isZero();
      checkOcspHistory(
          CertReader.getX509FromP12(certPath, clientKeystorePassw).getSerialNumber(), 1);
    } else {
      assertThat(UseCase.exec(certPath))
          .as("Expecting an invalid use case execution.")
          .isEqualTo(1);
    }
  }

  private void waitForOcspCacheToExpire() {
    final int seconds = ocspSettings.getGracePeriodSeconds();
    waitForOcspCacheToExpire(seconds);
  }

  private void waitForOcspCacheToExpire(int seconds) {
    seconds = seconds + 5;
    log.info("Waiting {} seconds for ocsp cache to expire.", seconds);
    waitSeconds(seconds);
  }

  private Path getPathOfFirstValidCert() {
    final String keystoreValidCertsPath =
        TestConfigManager.getTestsuiteConfig().getClient().getKeystorePathValidCerts();

    final Path certPath =
        CertificateProvider.getFilesFromDir(
                PkitsTestsuiteUtils.buildAbsolutePath(keystoreValidCertsPath).toString())
            .findFirst()
            .orElseThrow();
    log.info("Certificate path: {}", certPath);
    return certPath;
  }

  private void checkOcspHistory(
      @NonNull final BigInteger certSerialNr, final int expectedRequestAmount) {
    if (ocspSettings.isRequestsExpected()) {
      OcspHistory.check(ocspRespUri, certSerialNr, expectedRequestAmount);
    }
  }
}
