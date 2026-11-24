/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.sut.server.core.tsl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.gematik.pki.pkits.sut.server.core.configs.TslProcurerProperties;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import kong.unirest.core.Config;
import kong.unirest.core.GetRequest;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class InternetTslSourceTest {

  @Test
  void shouldReturnFixedInternetUrls() throws URISyntaxException, MalformedURLException {
    final TslProcurerProperties tslProcurerProperties = new TslProcurerProperties();
    tslProcurerProperties.setTimeoutMilliseconds(100);
    tslProcurerProperties.setInitialTslDownloadUrl(
        new java.net.URI("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0").toURL());

    final InternetTslSource source = new InternetTslSource(tslProcurerProperties);

    assertThat(source.getInitialTslUrl())
        .isEqualTo("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0");
    assertThat(source.getPrimaryTslUrl(null))
        .isEqualTo(Optional.of("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0"));
    assertThat(source.getBackupTslUrl(null)).isEmpty();
  }

  @Test
  void shouldSkipDownloadWhenOnlineHashMatchesCurrentHash() throws Exception {
    final InternetTslSource source = new InternetTslSource(createProperties());
    final Tsl currentTsl = new Tsl("same-hash", readSampleTsl());

    try (final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      mockUnirestConfig(unirestMock);

      final GetRequest hashRequest = mock(GetRequest.class);
      final HttpResponse<String> hashResponse = mockStringResponse(HttpStatus.SC_OK, "same-hash");
      when(hashRequest.asString()).thenReturn(hashResponse);
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.sha2?activeTslSeqNr=0"))
          .thenReturn(hashRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl)).isEmpty();
      verify(hashRequest).asString();
    }
  }

  @Test
  void shouldNotUseBackupHashWhenPrimaryHashLookupFails() throws Exception {
    final InternetTslSource source = new InternetTslSource(createProperties());
    final Tsl currentTsl = new Tsl("old-hash", readSampleTsl());

    try (final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      mockUnirestConfig(unirestMock);

      assertThat(source.getBackupTslUrl(currentTsl)).isEmpty();

      final GetRequest primaryHashRequest = mock(GetRequest.class);
      when(primaryHashRequest.asString()).thenThrow(new UnirestException("primary hash down"));
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.sha2?activeTslSeqNr=0"))
          .thenReturn(primaryHashRequest);

      final GetRequest primaryDownloadRequest = mock(GetRequest.class);
      final HttpResponse<byte[]> failedResponse =
          mockBytesResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, new byte[] {1});
      when(primaryDownloadRequest.asBytes())
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(failedResponse);
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0"))
          .thenReturn(primaryDownloadRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl)).isEmpty();
      verify(primaryHashRequest).asString();
      verify(primaryDownloadRequest, times(4)).asBytes();
    }
  }

  @Test
  void shouldAttemptPrimaryDownloadWhenHashCheckCannotBeVerified() throws Exception {
    final InternetTslSource source = new InternetTslSource(createProperties());
    final byte[] downloadedBytes = readSampleTsl();
    final Tsl currentTsl = new Tsl("old-hash", downloadedBytes);

    try (final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      mockUnirestConfig(unirestMock);

      final GetRequest primaryHashRequest = mock(GetRequest.class);
      when(primaryHashRequest.asString()).thenThrow(new UnirestException("primary hash down"));
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.sha2?activeTslSeqNr=0"))
          .thenReturn(primaryHashRequest);

      final GetRequest primaryDownloadRequest = mock(GetRequest.class);
      final HttpResponse<byte[]> failedResponse =
          mockBytesResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, new byte[] {1});
      when(primaryDownloadRequest.asBytes())
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(failedResponse);
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0"))
          .thenReturn(primaryDownloadRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl)).isEmpty();
      verify(primaryHashRequest).asString();
      verify(primaryDownloadRequest, times(4)).asBytes();
    }
  }

  @Test
  void shouldRetryPrimaryDownloadsUntilSuccess() throws Exception {
    final InternetTslSource source = new InternetTslSource(createProperties());
    final byte[] downloadedBytes = readSampleTsl();
    final Tsl currentTsl = new Tsl("old-hash", downloadedBytes);

    try (final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      mockUnirestConfig(unirestMock);

      final GetRequest hashRequest = mock(GetRequest.class);
      final HttpResponse<String> hashResponse = mockStringResponse(HttpStatus.SC_OK, "new-hash");
      when(hashRequest.asString()).thenReturn(hashResponse);
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.sha2?activeTslSeqNr=0"))
          .thenReturn(hashRequest);

      final GetRequest primaryDownloadRequest = mock(GetRequest.class);
      final HttpResponse<byte[]> failedResponse =
          mockBytesResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, new byte[] {1});
      final HttpResponse<byte[]> successResponse =
          mockBytesResponse(HttpStatus.SC_OK, downloadedBytes);
      when(primaryDownloadRequest.asBytes())
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(successResponse);
      unirestMock
          .when(() -> Unirest.get("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0"))
          .thenReturn(primaryDownloadRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl))
          .hasValueSatisfying(result -> assertThat(result.tslBytes).isEqualTo(downloadedBytes));

      verify(primaryDownloadRequest, times(3)).asBytes();
    }
  }

  private TslProcurerProperties createProperties() throws Exception {
    final TslProcurerProperties tslProcurerProperties = new TslProcurerProperties();
    tslProcurerProperties.setTimeoutMilliseconds(100);
    tslProcurerProperties.setInitialTslDownloadUrl(
        java.net
            .URI
            .create("https://download.tsl.gematik.de/tsl/tsl.xml?activeTslSeqNr=0")
            .toURL());
    return tslProcurerProperties;
  }

  private void mockUnirestConfig(final MockedStatic<Unirest> unirestMock) {
    final Config config = mock(Config.class);
    when(config.reset()).thenReturn(config);
    when(config.connectTimeout(anyInt())).thenReturn(config);
    unirestMock.when(Unirest::config).thenReturn(config);
  }

  @SuppressWarnings("unchecked")
  private HttpResponse<String> mockStringResponse(final int status, final String body) {
    final HttpResponse<String> response = mock(HttpResponse.class);
    when(response.getStatus()).thenReturn(status);
    when(response.getBody()).thenReturn(body);
    return response;
  }

  @SuppressWarnings("unchecked")
  private HttpResponse<byte[]> mockBytesResponse(final int status, final byte[] body) {
    final HttpResponse<byte[]> response = mock(HttpResponse.class);
    when(response.getStatus()).thenReturn(status);
    when(response.getBody()).thenReturn(body);
    return response;
  }

  private byte[] readSampleTsl() throws IOException {
    final Path tslPath =
        Path.of(
                System.getProperty("user.dir"),
                "..",
                "pkits-sut-server-sim",
                "src",
                "test",
                "resources",
                "TSL_default.xml")
            .normalize();
    return Files.readAllBytes(tslPath);
  }
}
