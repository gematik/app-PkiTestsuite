/*
 * Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.tsl.provider.controller;

import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_HASH_PRIMARY_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_SEQNR_PARAM_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_BACKUP_ENDPOINT;
import static de.gematik.pki.pkits.common.PkitsConstants.TSL_XML_PRIMARY_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.pkits.tsl.provider.TslConfigHolder;
import de.gematik.pki.pkits.tsl.provider.api.TslProviderManager;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderConfigDto;
import de.gematik.pki.pkits.tsl.provider.data.TslProviderEndpointsConfig;
import java.nio.charset.StandardCharsets;
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

  private String getLocalhostEndpoint(final String endpoint) {
    return "http://localhost:" + localServerPort + endpoint;
  }

  @Test
  void verifyTslXmlEndpoint() {
    initTslProviderConfiguration();
    final byte[] responseDownload =
        Unirest.get(getLocalhostEndpoint(TSL_XML_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, 1)
            .asBytes()
            .getBody();
    assertThat(responseDownload).hasSize(TSL_DUMMY.length());
  }

  @Test
  void tslXmlEndpointZeroLengthTslHttp500() {
    initTslProviderConfiguration("");
    final HttpResponse<byte[]> httpResponse =
        Unirest.get(getLocalhostEndpoint(TSL_XML_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  @Test
  void tslHashEndpointZeroLengthTslHttp500() {
    initTslProviderConfiguration("");
    final HttpResponse<byte[]> httpResponse =
        Unirest.get(getLocalhostEndpoint(TSL_HASH_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  @Test
  void verifyTslHashEndpoint() {
    initTslProviderConfiguration();
    final HttpResponse<String> responseDownload =
        Unirest.get(getLocalhostEndpoint(TSL_HASH_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asString();
    assertThat(responseDownload.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(responseDownload.getBody()).hasSize(HASH_LENGTH);
  }

  @Test
  void verifyTslXmlBackupEndpoint() {
    initTslProviderConfiguration();
    final byte[] responseDownload =
        Unirest.get(getLocalhostEndpoint(TSL_XML_BACKUP_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes()
            .getBody();
    assertThat(responseDownload).hasSize(TSL_DUMMY.length());
  }

  @Test
  void verifyTslHashBackupEndpoint() {
    initTslProviderConfiguration();
    final HttpResponse<String> responseDownload =
        Unirest.get(getLocalhostEndpoint(TSL_HASH_BACKUP_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asString();
    assertThat(responseDownload.getStatus()).isEqualTo(HttpStatus.SC_OK);
    assertThat(responseDownload.getBody()).hasSize(HASH_LENGTH);
  }

  @Test
  void tslXmlEndpointWithoutTslHttp500() {
    clearTslProviderConfiguration();
    final HttpResponse<byte[]> httpResponse =
        Unirest.get(getLocalhostEndpoint(TSL_XML_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  @Test
  void tslHashEndpointWithoutHashHttp500() {
    clearTslProviderConfiguration();
    final HttpResponse<byte[]> httpResponse =
        Unirest.get(getLocalhostEndpoint(TSL_HASH_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();
    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
  }

  @Test
  void clearAndNotConfiguredTsl() {
    TslProviderManager.clear(getLocalhostEndpoint(""));

    final HttpResponse<byte[]> httpResponse =
        Unirest.get(getLocalhostEndpoint(TSL_XML_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();

    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
    assertThat(new String(httpResponse.getBody(), StandardCharsets.UTF_8))
        .isEqualTo(NOT_CONFIGURED);
  }

  @Test
  void clearAndNotConfiguredHash() {
    TslProviderManager.clear(getLocalhostEndpoint(""));

    final HttpResponse<byte[]> httpResponse =
        Unirest.get(getLocalhostEndpoint(TSL_HASH_PRIMARY_ENDPOINT))
            .queryString(TSL_SEQNR_PARAM_ENDPOINT, "42")
            .asBytes();

    assertThat(httpResponse.getStatus()).isEqualTo(HttpStatus.SC_INTERNAL_SERVER_ERROR);
    assertThat(new String(httpResponse.getBody(), StandardCharsets.UTF_8))
        .isEqualTo(NOT_CONFIGURED);
  }

  private void initTslProviderConfiguration() {
    initTslProviderConfiguration(TSL_DUMMY);
  }

  private void initTslProviderConfiguration(final String tslStr) {
    tslConfigHolder.setTslProviderConfigDto(
        new TslProviderConfigDto(
            tslStr.getBytes(StandardCharsets.UTF_8),
            TslProviderEndpointsConfig.PRIMARY_200_BACKUP_200));
  }

  private void clearTslProviderConfiguration() {
    tslConfigHolder.setTslProviderConfigDto(null);
  }
}
