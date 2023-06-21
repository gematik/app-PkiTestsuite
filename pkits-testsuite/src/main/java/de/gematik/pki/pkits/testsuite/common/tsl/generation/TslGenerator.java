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

package de.gematik.pki.pkits.testsuite.common.tsl.generation;

import static de.gematik.pki.pkits.common.PkitsConstants.GEMATIK_TEST_TSP;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.AggregateTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.AggregateTslOperation.AggregateTslOperationBuilder;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.ChangNameTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.PersistTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.SignTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.StandardTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.StandardTslOperation.StandardTslOperationConfig;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.reporting.CurrentTestInfo;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Builder
public class TslGenerator {

  public static final String TRUST_ANCHOR_TEMPLATES_DIRNAME =
      "./testDataTemplates/certificates/ecc/trustAnchor/";

  public static final Path invalideSignatureSignerPath =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_invalid-signature.p12");

  public static final Path tslSignerFromNotYetValidTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_notyetvalid_ta.p12");
  public static final Path tslSignerExpired =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_expired.p12");

  public static final Path tslSignerNotYetValid =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_not-yet-valid.p12");

  public static final Path tslSignerInvalidKeyusage =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_invalid-keyusage.p12");

  public static final Path tslSignerInvalidExtendedKeyusage =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_invalid-ext-keyusage.p12");

  public static final Path alternativeTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-9-TEST-ONLY.p12");

  public static final Path alternativeSecondTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-16-TEST-ONLY.p12");

  public static final Path tslSignerFromExpiredTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_expired_ta.p12");

  public static final TslOperation NO_TSL_MODIFICATIONS = null;
  private static final int TSL_DAYS_UNTIL_NEXTUPDATE = 90;
  private static final int WEB_SERVER_START_TIMEOUT_SECS = 30;

  protected final CurrentTestInfo currentTestInfo;
  protected final String tslName;

  private int tslDownloadIntervalSeconds;
  private int tslProcessingTimeSeconds;
  protected String ocspRespUri;
  protected String tslProvUri;
  protected Path defaultTslSigner;
  protected String tslSignerKeystorePassw;

  @Getter @Setter protected int tslSeqNr;

  @Builder.Default private TslOperation modifyTsl = null;

  public TslDownload getTslDownloadWithTemplateAndSigner(
      final int offeredSeqNr,
      final TrustStatusListType tsl,
      final Path tslSignerP12Path,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {
    return getTslDownloadWithTemplateAndSigner(
        null, offeredSeqNr, tsl, tslSignerP12Path, signerKeyUsageCheck, signerValidityCheck);
  }

  public TslDownload getTslDownloadWithTemplateAndSigner(
      final Path tslOutputFile,
      final int offeredSeqNr,
      final TrustStatusListType tsl,
      final Path tslSignerP12Path,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {

    final AggregateTslOperationBuilder aggregateBuilder = AggregateTslOperation.builder();

    aggregateBuilder.chained(getStandardTslOperation(offeredSeqNr));
    aggregateBuilder.chained(new ChangNameTslOperation(tslName));

    aggregateBuilder.chained(
        new SignTslOperation(
            tslSignerP12Path, tslSignerKeystorePassw, signerKeyUsageCheck, signerValidityCheck));

    if (modifyTsl != null) {
      aggregateBuilder.chained(modifyTsl);
    }

    if (tslOutputFile == null) {
      aggregateBuilder.chained(new PersistTslOperation(currentTestInfo, tslName));
    } else {
      aggregateBuilder.chained(new PersistTslOperation(tslOutputFile));
    }

    final byte[] tslBytes = aggregateBuilder.build().apply(tsl).getAsTslBytes();

    return getTslDownload(tslBytes, tslSignerP12Path);
  }

  public TslDownload getStandardTslDownload(final TrustStatusListType tsl) {
    return getStandardTslDownload(tsl, defaultTslSigner);
  }

  public TslDownload getStandardTslDownload(
      final TrustStatusListType tsl, final Path tslSignerP12Path) {

    return getTslDownloadWithTemplateAndSigner(
        tslSeqNr,
        tsl,
        tslSignerP12Path,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);
  }

  public TslDownload getTslDownload(final byte[] tslBytes, final Path tslSignerP12Path) {

    final P12Container tslSignerP12 =
        P12Reader.getContentFromP12(
            GemLibPkiUtils.readContent(tslSignerP12Path), tslSignerKeystorePassw);

    final X509Certificate tslSignerCert = tslSignerP12.getCertificate();

    return TslDownload.builder()
        .tslBytes(tslBytes)
        .tslDownloadIntervalSeconds(tslDownloadIntervalSeconds + 5)
        .tslProcessingTimeSeconds(tslProcessingTimeSeconds)
        .tslProvUri(tslProvUri)
        .ocspRespUri(ocspRespUri)
        .tslDownloadPoint(TSL_DOWNLOAD_POINT_PRIMARY)
        .tslSignerCert(tslSignerCert)
        .build();
  }

  public TslOperation signTslOperation(@NonNull final Path tslSignerPath) {

    return new SignTslOperation(
        tslSignerPath,
        tslSignerKeystorePassw,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);
  }

  public String getTslDownloadUrlPrimary(final int seqNr) {
    return tslProvUri + TSL_XML_PRIMARY_ENDPOINT + "?" + TSL_SEQNR_PARAM_ENDPOINT + "=" + seqNr;
  }

  public String getTslDownloadUrlBackup(final int seqNr) {
    return tslProvUri + TSL_XML_BACKUP_ENDPOINT + "?" + TSL_SEQNR_PARAM_ENDPOINT + "=" + seqNr;
  }

  public TslOperation getStandardTslOperation(final int offeredSeqNr) {
    final StandardTslOperationConfig standardTslOperationConfig =
        StandardTslOperationConfig.builder()
            .sequenceNr(offeredSeqNr)
            .tspName(GEMATIK_TEST_TSP)
            .newSsp(ocspRespUri + OCSP_SSP_ENDPOINT + "/" + offeredSeqNr)
            .tslDownloadUrlPrimary(getTslDownloadUrlPrimary(offeredSeqNr))
            .tslDownloadUrlBackup(getTslDownloadUrlBackup(offeredSeqNr))
            .issueDate(ZonedDateTime.now(ZoneOffset.UTC))
            .nextUpdate(null)
            .daysUntilNextUpdate(TSL_DAYS_UNTIL_NEXTUPDATE)
            .build();
    return new StandardTslOperation(standardTslOperationConfig);
  }
}
