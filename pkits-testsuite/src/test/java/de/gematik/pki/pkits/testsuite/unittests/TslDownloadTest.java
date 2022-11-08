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

package de.gematik.pki.pkits.testsuite.unittests;

import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.common.tsl.TslDownload;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TslSettings;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class TslDownloadTest {

  private static final TslSettings tslSettings =
      TestConfigManager.getTestSuiteConfig().getTestSuiteParameter().getTslSettings();
  private static final Path tslSigner = tslSettings.getSigner();
  private static final String tslSignerPassword = tslSettings.getSignerPassword();

  private static final TslDownload tslDownload =
      TslDownload.builder()
          .tslBytes("my little TSL :-)".getBytes())
          .tslDownloadTimeoutSecs(3)
          .tslProcessingTimeSeconds(3)
          .tslProvUri("http://tsl...")
          .ocspRespUri("http://ocsp...")
          .ocspRequestExpected(true)
          .tslDownloadPoint(TSL_DOWNLOAD_POINT_PRIMARY)
          .tslSignerCert(readTslSignerCert())
          .build();

  @Test
  void constructWithDefaults() {
    final TslDownload tslDownload =
        TslDownload.builder()
            .tslBytes("my little TSL :-)".getBytes())
            .tslProvUri("http://tsl...")
            .ocspRespUri("http://ocsp...")
            .tslDownloadPoint(TSL_DOWNLOAD_POINT_PRIMARY)
            .tslSignerCert(readTslSignerCert())
            .build();
    assertThat(tslDownload.getTslDownloadTimeoutSecs()).isEqualTo(1);
    assertThat(tslDownload.getTslProcessingTimeSeconds()).isEqualTo(3);
    assertThat(tslDownload.isOcspRequestExpected()).isTrue();
  }

  @Test
  void waitUntilTslDownloadCompleted() {
    assertThatThrownBy(tslDownload::waitUntilTslDownloadCompleted)
        .isInstanceOf(PkiCommonException.class);
  }

  private static X509Certificate readTslSignerCert() {
    return CertReader.getX509FromP12(tslSigner, tslSignerPassword);
  }
}
