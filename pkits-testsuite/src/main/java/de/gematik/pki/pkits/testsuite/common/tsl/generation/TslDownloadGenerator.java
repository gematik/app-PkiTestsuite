/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.common.tsl.generation;

import static de.gematik.pki.pkits.common.PkitsConstants.GEMATIK_TEST_TSP;
import static de.gematik.pki.pkits.common.PkitsConstants.OCSP_SSP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsTestDataConstants.TSL_DEFAULT_TTL_DAYS;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_KEY_USAGE_CHECK_ENABLED;
import static de.gematik.pki.pkits.testsuite.common.tsl.generation.TslGenerationConstants.SIGNER_VALIDITY_CHECK_ENABLED;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.AggregateTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.AggregateTslOperation.AggregateTslOperationBuilder;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.ChangNameTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.SignTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.StandardTslOperation;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.StandardTslOperation.StandardTslOperationConfig;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TslOperation;
import de.gematik.pki.pkits.testsuite.reporting.CurrentTestInfo;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Objects;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Builder
public class TslDownloadGenerator {

  public static final String TSL_NAME_DEFAULT = "defaultTsl";
  public static final String TSL_NAME_ALTERNATIVE = "alternativeTsl";

  public static final String TRUST_ANCHOR_TEMPLATES_DIRNAME =
      "./testDataTemplates/certificates/ecc/trustAnchor/";

  public static final Path invalideSignatureSignerPath =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_invalid-signature.p12");

  public static final Path tslSignerFromNotYetValidTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_not-yet-valid_ta.p12");
  public static final Path tslSignerExpired =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_expired.p12");

  public static final Path tslSignerNotYetValid =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_not-yet-valid.p12");

  public static final Path tslSignerInvalidKeyusage =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_invalid-keyusage.p12");

  public static final Path tslSignerInvalidExtendedKeyusage =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "ee_invalid-ext-keyusage.p12");

  public static final Path alternativeTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-52-TEST-ONLY.p12");

  public static final Path alternativeSecondTslSignerP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "TSL-Signing-Unit-53-TEST-ONLY.p12");

  public static final Path tslSignerFromExpiredTrustAnchorP12Path =
      Path.of(TRUST_ANCHOR_TEMPLATES_DIRNAME, "valid_tsl_signer_from_expired_ta.p12");

  public static final TslOperation NO_TSL_MODIFICATIONS = null;
  private static final int WEB_SERVER_START_TIMEOUT_SECS = 30;

  protected final CurrentTestInfo currentTestInfo;
  protected final String tslName;

  private int tslDownloadIntervalSeconds;
  private int tslProcessingTimeSeconds;
  private int ocspProcessingTimeSeconds;

  protected String ocspResponderUri;
  protected String tslProviderUri;

  protected P12Container tslSigner;
  protected X509Certificate trustAnchor;

  protected P12Container ocspSigner;

  @Getter @Setter protected int tslDaysUntilNextupdate = TSL_DEFAULT_TTL_DAYS;

  @Getter @Setter protected int tslSeqNr;

  @Builder.Default private TslOperation modifyTsl = null;

  public TslDownload getTslDownloadWithTemplateAndSigner(
      final int offeredTslSeqNr,
      final TrustStatusListType tsl,
      final P12Container tslSigner,
      final X509Certificate trustAnchor,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {
    return getTslDownloadWithTemplateAndSigner(
        null,
        offeredTslSeqNr,
        tsl,
        tslSigner,
        trustAnchor,
        signerKeyUsageCheck,
        signerValidityCheck);
  }

  public TslDownload getTslDownloadWithTemplateAndSigner(
      final Path tslOutputFile,
      final int offeredTslSeqNr,
      final TrustStatusListType tslUnsigned,
      final P12Container tslSigner,
      final X509Certificate trustAnchor,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {

    final AggregateTslOperationBuilder aggregateBuilder = AggregateTslOperation.builder();

    aggregateBuilder.chained(getStandardTslOperation(offeredTslSeqNr));
    aggregateBuilder.chained(new ChangNameTslOperation("gematik Test-TSL: " + tslName));

    aggregateBuilder.chained(
        new SignTslOperation(tslSigner, signerKeyUsageCheck, signerValidityCheck));

    // NOTE: depending on the actions performed in modifyTsl, this step can invalide the signature
    // generated by the default/above SignTslOperation; if required that the resulting TSL is
    // signed, make
    // sure that modifyTsl also executes SignTslOperation at the end.
    if (modifyTsl != null) {
      aggregateBuilder.chained(modifyTsl);
    }

    final byte[] tslUnsignedBytes =
        aggregateBuilder.build().apply(tslUnsigned).getAsTslUnsignedBytes();

    final Path tslFilePathToUse;
    tslFilePathToUse =
        Objects.requireNonNullElseGet(
            tslOutputFile,
            () ->
                PersistTslUtils.generateTslFilename(
                    currentTestInfo, tslName, TslConverter.bytesToTslUnsigned(tslUnsignedBytes)));

    PersistTslUtils.saveBytes(tslFilePathToUse, tslUnsignedBytes);

    return getTslDownload(tslUnsignedBytes, tslSigner, trustAnchor);
  }

  public TslDownload getStandardTslDownload(final TrustStatusListType tsl) {
    return getStandardTslDownload(tsl, tslSigner, trustAnchor);
  }

  public TslDownload getStandardTslDownload(
      final TrustStatusListType tsl,
      final P12Container tslSigner,
      final X509Certificate trustAnchor) {

    return getTslDownloadWithTemplateAndSigner(
        tslSeqNr,
        tsl,
        tslSigner,
        trustAnchor,
        SIGNER_KEY_USAGE_CHECK_ENABLED,
        SIGNER_VALIDITY_CHECK_ENABLED);
  }

  public TslDownload getTslDownload(
      final byte[] tslBytes, final P12Container tslSignerP12, final X509Certificate trustAnchor) {

    final X509Certificate tslSignerCert = tslSignerP12.getCertificate();

    return TslDownload.builder()
        .tslBytes(tslBytes)
        .tslDownloadIntervalSeconds(tslDownloadIntervalSeconds)
        .tslProcessingTimeSeconds(tslProcessingTimeSeconds)
        .ocspProcessingTimeSeconds(ocspProcessingTimeSeconds)
        .tslProvUri(tslProviderUri)
        .ocspRespUri(ocspResponderUri)
        .tslSignerCert(tslSignerCert)
        .trustAnchor(trustAnchor)
        .ocspSigner(ocspSigner)
        .build();
  }

  public TslOperation signTslOperation(@NonNull final P12Container tslSigner) {

    return new SignTslOperation(
        tslSigner, SIGNER_KEY_USAGE_CHECK_ENABLED, SIGNER_VALIDITY_CHECK_ENABLED);
  }

  public String getTslDownloadUrlPrimary(final int tslSeqNr) {
    return tslProviderUri
        + TSL_XML_PRIMARY_ENDPOINT
        + "?"
        + TSL_SEQNR_PARAM_ENDPOINT
        + "="
        + tslSeqNr;
  }

  public String getTslDownloadUrlBackup(final int tslSeqNr) {
    return tslProviderUri
        + TSL_XML_BACKUP_ENDPOINT
        + "?"
        + TSL_SEQNR_PARAM_ENDPOINT
        + "="
        + tslSeqNr;
  }

  public TslOperation getStandardTslOperation(final int offeredTslSeqNr) {
    final StandardTslOperationConfig standardTslOperationConfig =
        StandardTslOperationConfig.builder()
            .tslSeqNr(offeredTslSeqNr)
            .tspName(GEMATIK_TEST_TSP)
            .newSsp(ocspResponderUri + OCSP_SSP_ENDPOINT + "/" + offeredTslSeqNr)
            .tslDownloadUrlPrimary(getTslDownloadUrlPrimary(offeredTslSeqNr))
            .tslDownloadUrlBackup(getTslDownloadUrlBackup(offeredTslSeqNr))
            .issueDate(GemLibPkiUtils.now())
            .nextUpdate(null)
            .daysUntilNextUpdate(tslDaysUntilNextupdate)
            .build();
    return new StandardTslOperation(standardTslOperationConfig);
  }
}
