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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsConstants.*;
import static de.gematik.pki.pkits.common.PkitsConstants.TslDownloadPoint.TSL_DOWNLOAD_POINT_PRIMARY;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@TestComponent
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
class TslProviderControllerTest {

  private static final int HASH_LENGTH = 64;
  private static final String TSL_DUMMY = "this is a very short TSL :-)";

  @Autowired private TslConfigHolder tslConfigHolder;
  @LocalServerPort private int localServerPort;

  @Test
  void verifyTslXmlEndpoint() {
    initTslProviderConfiguration();
    final byte[] responseDownload =
        Unirest.get("http://localhost:" + localServerPort + TSL_XML_ENDPOINT)
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, 1)
            .asBytes()
            .getBody();
    assertThat(responseDownload).hasSize(TSL_DUMMY.length());
  }

  @Test
  void verifyTslHashEndpoint() {
    initTslProviderConfiguration();
    final HttpResponse<String> responseDownload =
        Unirest.get("http://localhost:" + localServerPort + TSL_HASH_ENDPOINT).asString();
    assertThat(responseDownload.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(responseDownload.getBody()).hasSize(HASH_LENGTH);
  }

  @Test
  void verifyTslXmlBackupEndpoint() {
    initTslProviderConfiguration();
    final byte[] responseDownload =
        Unirest.get("http://localhost:" + localServerPort + TSL_XML_BACKUP_ENDPOINT)
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes()
            .getBody();
    assertThat(responseDownload).hasSize(TSL_DUMMY.length());
  }

  @Test
  void verifyTslHashBackupEndpoint() {
    initTslProviderConfiguration();
    final HttpResponse<String> responseDownload =
        Unirest.get("http://localhost:" + localServerPort + TSL_HASH_BACKUP_ENDPOINT).asString();
    assertThat(responseDownload.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(responseDownload.getBody()).hasSize(HASH_LENGTH);
  }

  @Test
  void tslXmlEndpointWithoutTslHttp500() {
    clearTslProviderConfiguration();
    final HttpResponse<byte[]> httpResponse =
        Unirest.get("http://localhost:" + localServerPort + TSL_XML_ENDPOINT)
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  @Test
  void tslHashEndpointWithoutHashHttp500() {
    clearTslProviderConfiguration();
    final HttpResponse<byte[]> httpResponse =
        Unirest.get("http://localhost:" + localServerPort + TSL_HASH_ENDPOINT).asBytes();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  private void initTslProviderConfiguration() {
    tslConfigHolder.setTslProviderConfigDto(
        new TslProviderConfigDto(TSL_DUMMY.getBytes(), TSL_DOWNLOAD_POINT_PRIMARY));
  }

  private void clearTslProviderConfiguration() {
    tslConfigHolder.setTslProviderConfigDto(null);
  }
}
