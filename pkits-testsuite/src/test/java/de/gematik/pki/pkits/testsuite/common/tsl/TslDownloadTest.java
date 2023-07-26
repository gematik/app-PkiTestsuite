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

package de.gematik.pki.pkits.testsuite.common.tsl;

import static de.gematik.pki.pkits.tsl.provider.data.TslRequestHistory.IGNORE_SEQUENCE_NUMBER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import de.gematik.pki.pkits.testsuite.config.OcspSettings;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TslSettings;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class TslDownloadTest {

  private static final TslSettings tslSettings =
      TestConfigManager.getTestSuiteConfig().getTestSuiteParameter().getTslSettings();
  private static final Path tslSigner = tslSettings.getSigner();
  private static final String tslSignerPassword = tslSettings.getSignerPassword();

  private static final P12Container ocspSigner;

  static {
    final OcspSettings ocspSettings =
        TestConfigManager.getTestSuiteConfig().getTestSuiteParameter().getOcspSettings();

    ocspSigner =
        P12Reader.getContentFromP12(
            ocspSettings.getKeystorePathOcsp().resolve(TestSuiteConstants.OCSP_SIGNER_FILENAME),
            ocspSettings.getSignerPassword());
  }

  private static final TslDownload tslDownload =
      TslDownload.builder()
          .tslBytes("my little TSL :-)".getBytes(StandardCharsets.UTF_8))
          .tslDownloadIntervalSeconds(3)
          .tslProcessingTimeSeconds(3)
          .ocspProcessingTimeSeconds(1)
          .tslProvUri("http://tsl...")
          .ocspRespUri("http://ocsp...")
          .tslSignerCert(readTslSignerCert())
          .ocspSigner(ocspSigner)
          .build();

  @Test
  void constructWithDefaults() {
    final TslDownload tslDownload =
        TslDownload.builder()
            .tslBytes("my little TSL :-)".getBytes(StandardCharsets.UTF_8))
            .tslProvUri("http://tsl...")
            .ocspRespUri("http://ocsp...")
            .tslSignerCert(readTslSignerCert())
            .ocspSigner(ocspSigner)
            .build();
    assertThat(tslDownload.getTslDownloadIntervalSeconds()).isEqualTo(1);
    assertThat(tslDownload.getTslProcessingTimeSeconds()).isEqualTo(3);
    assertThat(tslDownload.getOcspProcessingTimeSeconds()).isEqualTo(1);
  }

  @Test
  void waitUntilTslDownloadCompleted() {
    assertThatThrownBy(
            () ->
                tslDownload.waitUntilTslDownloadCompleted(
                    IGNORE_SEQUENCE_NUMBER, IGNORE_SEQUENCE_NUMBER))
        .isInstanceOf(PkiCommonException.class);

    assertThatThrownBy(() -> tslDownload.waitForTslDownload(IGNORE_SEQUENCE_NUMBER))
        .isInstanceOf(PkiCommonException.class);
    assertThatThrownBy(
            () -> tslDownload.waitUntilTslDownloadCompletedOptional(IGNORE_SEQUENCE_NUMBER))
        .isInstanceOf(PkiCommonException.class);
  }

  @Test
  void tslByteToStringConversionBidirectional() {
    final TslDownload tslDownload =
        TslDownload.builder()
            .tslBytes("my little TSL :-)".getBytes(StandardCharsets.UTF_8))
            .tslProvUri("http://tsl...")
            .ocspRespUri("http://ocsp...")
            .tslSignerCert(readTslSignerCert())
            .ocspSigner(ocspSigner)
            .build();

    final String tslStrBefore = new String(tslDownload.getTslBytes(), StandardCharsets.UTF_8);

    final byte[] tslBytes = tslStrBefore.getBytes();
    assertThat(Arrays.equals(tslBytes, tslDownload.getTslBytes())).isTrue();

    final String tslStrAfter = new String(tslBytes, StandardCharsets.UTF_8);
    assertThat(tslStrBefore).isEqualTo(tslStrAfter);
  }

  private static X509Certificate readTslSignerCert() {
    return CertReader.getX509FromP12(tslSigner, tslSignerPassword);
  }
}
