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

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.tsl.TslReader;
import de.gematik.pki.pkits.sut.server.core.configs.TslProcurerProperties;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import kong.unirest.core.Config;
import kong.unirest.core.GetRequest;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class DefaultTslSourceTest {

  @Test
  void shouldResolveConfiguredAndParsedTslUrls() throws Exception {
    final TslProcurerProperties tslProcurerProperties = new TslProcurerProperties();
    tslProcurerProperties.setInitialTslDownloadUrl(
        URI.create("http://example.test/tsl.xml").toURL());
    tslProcurerProperties.setTimeoutMilliseconds(100);

    final DefaultTslSource source = new DefaultTslSource(tslProcurerProperties);
    final Tsl currentTsl = new Tsl("hash", readSampleTsl());

    assertThat(source.getInitialTslUrl()).isEqualTo("http://example.test/tsl.xml");
    assertThat(source.getPrimaryTslUrl(currentTsl))
        .hasValue(
            "http://ocsp-sim01-test.gem.telematik-test:8080/TSL_TCL_Service/TSL/?activeTSL=TSL_default-seq1");
    assertThat(source.getBackupTslUrl(currentTsl))
        .hasValue(
            "http://ocsp-sim01-test.gem.telematik-test:8080/TSL_TCL_Service/TSL-backup/?activeTSL=TSL_default-seq1");
  }

  @Test
  void shouldReturnEmptyWhenTslUrlsCannotBeExtracted() throws Exception {
    final DefaultTslSource source = new DefaultTslSource(createProperties());
    final Tsl currentTsl = new Tsl("hash", readSampleTsl());

    try (final MockedStatic<TslReader> tslReaderMock = mockStatic(TslReader.class)) {
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlPrimary(currentTsl.tslUnsigned))
          .thenThrow(new GemPkiRuntimeException("primary missing"));
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlBackup(currentTsl.tslUnsigned))
          .thenThrow(new GemPkiRuntimeException("backup missing"));

      assertThat(source.getPrimaryTslUrl(currentTsl)).isEmpty();
      assertThat(source.getBackupTslUrl(currentTsl)).isEmpty();
    }
  }

  @Test
  void shouldSkipDownloadWhenPrimaryHashMatchesCurrentTsl() throws Exception {
    final DefaultTslSource source = new DefaultTslSource(createProperties());
    final Tsl currentTsl = new Tsl("same-hash", readSampleTsl());
    final String primaryUrl = "http://example.test/tsl.xml";

    try (final MockedStatic<TslReader> tslReaderMock = mockStatic(TslReader.class);
        final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlPrimary(currentTsl.tslUnsigned))
          .thenReturn(primaryUrl);
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlBackup(currentTsl.tslUnsigned))
          .thenReturn("http://backup.example.test/tsl.xml");
      mockUnirestConfig(unirestMock);

      final GetRequest hashRequest = mock(GetRequest.class);
      final HttpResponse<String> hashResponse = mockStringResponse(HttpStatus.SC_OK, "same-hash");
      when(hashRequest.asString()).thenReturn(hashResponse);
      unirestMock.when(() -> Unirest.get("http://example.test/tsl.sha2")).thenReturn(hashRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl)).isEmpty();
      verify(hashRequest).asString();
    }
  }

  @Test
  void shouldUseBackupHashWhenPrimaryHashLookupFails() throws Exception {
    final DefaultTslSource source = new DefaultTslSource(createProperties());
    final Tsl currentTsl = new Tsl("same-hash", readSampleTsl());
    final String primaryUrl = "http://example.test/tsl.xml";
    final String backupUrl = "http://backup.example.test/tsl.xml";

    try (final MockedStatic<TslReader> tslReaderMock = mockStatic(TslReader.class);
        final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlPrimary(currentTsl.tslUnsigned))
          .thenReturn(primaryUrl);
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlBackup(currentTsl.tslUnsigned))
          .thenReturn(backupUrl);
      mockUnirestConfig(unirestMock);

      final GetRequest primaryHashRequest = mock(GetRequest.class);
      when(primaryHashRequest.asString()).thenThrow(new UnirestException("primary hash down"));
      unirestMock
          .when(() -> Unirest.get("http://example.test/tsl.sha2"))
          .thenReturn(primaryHashRequest);

      final GetRequest backupHashRequest = mock(GetRequest.class);
      final HttpResponse<String> backupHashResponse =
          mockStringResponse(HttpStatus.SC_OK, "same-hash");
      when(backupHashRequest.asString()).thenReturn(backupHashResponse);
      unirestMock
          .when(() -> Unirest.get("http://backup.example.test/tsl.sha2"))
          .thenReturn(backupHashRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl)).isEmpty();
      verify(primaryHashRequest).asString();
      verify(backupHashRequest).asString();
    }
  }

  @Test
  void shouldRetryPrimaryAndFallbackToBackupDownload() throws Exception {
    final DefaultTslSource source = new DefaultTslSource(createProperties());
    final byte[] downloadedBytes = readSampleTsl();
    final Tsl currentTsl = new Tsl("old-hash", downloadedBytes);
    final String primaryUrl = "http://example.test/tsl.xml";
    final String backupUrl = "http://backup.example.test/tsl.xml";

    try (final MockedStatic<TslReader> tslReaderMock = mockStatic(TslReader.class);
        final MockedStatic<Unirest> unirestMock = mockStatic(Unirest.class)) {
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlPrimary(currentTsl.tslUnsigned))
          .thenReturn(primaryUrl);
      tslReaderMock
          .when(() -> TslReader.getTslDownloadUrlBackup(currentTsl.tslUnsigned))
          .thenReturn(backupUrl);
      mockUnirestConfig(unirestMock);

      final GetRequest hashRequest = mock(GetRequest.class);
      final HttpResponse<String> hashResponse = mockStringResponse(HttpStatus.SC_OK, "new-hash");
      when(hashRequest.asString()).thenReturn(hashResponse);
      unirestMock.when(() -> Unirest.get("http://example.test/tsl.sha2")).thenReturn(hashRequest);

      final GetRequest primaryDownloadRequest = mock(GetRequest.class);
      final HttpResponse<byte[]> failedResponse =
          mockBytesResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR, new byte[] {1});
      when(primaryDownloadRequest.asBytes())
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(failedResponse)
          .thenReturn(failedResponse);
      unirestMock.when(() -> Unirest.get(primaryUrl)).thenReturn(primaryDownloadRequest);

      final GetRequest backupDownloadRequest = mock(GetRequest.class);
      final HttpResponse<byte[]> successResponse =
          mockBytesResponse(HttpStatus.SC_OK, downloadedBytes);
      when(backupDownloadRequest.asBytes()).thenReturn(successResponse);
      unirestMock.when(() -> Unirest.get(backupUrl)).thenReturn(backupDownloadRequest);

      assertThat(source.downloadTslIfHashIsDifferent(currentTsl))
          .hasValueSatisfying(result -> assertThat(result.tslBytes).isEqualTo(downloadedBytes));

      verify(primaryDownloadRequest, times(4)).asBytes();
      verify(backupDownloadRequest).asBytes();
    }
  }

  private TslProcurerProperties createProperties() throws Exception {
    final TslProcurerProperties tslProcurerProperties = new TslProcurerProperties();
    tslProcurerProperties.setInitialTslDownloadUrl(
        URI.create("http://example.test/tsl.xml").toURL());
    tslProcurerProperties.setTimeoutMilliseconds(100);
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
