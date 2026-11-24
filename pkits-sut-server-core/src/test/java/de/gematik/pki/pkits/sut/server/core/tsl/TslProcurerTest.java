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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TucPki001Verifier;
import de.gematik.pki.pkits.sut.server.core.configs.OcspProperties;
import de.gematik.pki.pkits.sut.server.core.configs.TslProcurerProperties;
import de.gematik.pki.pkits.sut.server.core.exceptions.TosException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class TslProcurerTest {

  @Test
  void shouldThrowWhenNoTslIsAvailableYet() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();

    try {
      assertThatThrownBy(tslProcurer::getTslInfoProv)
          .isInstanceOf(TosException.class)
          .hasMessageContaining("No tsl data available");
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldReturnTslInfoProviderWhenCurrentTslIsPresent() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();
    try {
      setField(tslProcurer, "currentTsl", new Tsl("hash", readSampleTsl()));

      assertThat(tslProcurer.getTslInfoProv()).isNotNull();
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldExposePrivateUrlAndHashHelpers() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();
    try {
      final Tsl currentTsl = new Tsl("same-hash", readSampleTsl());
      setField(tslProcurer, "currentTsl", currentTsl);

      assertThat(invoke(tslProcurer, "getInitialTslUrl")).isEqualTo("http://localhost:1/tsl.xml");
      assertThat(invoke(tslProcurer, "getPrimaryTslUrl"))
          .isEqualTo(Optional.of("http://localhost:1/tsl.xml"));
      assertThat(invoke(tslProcurer, "getTslBackupUrl"))
          .isEqualTo(Optional.of("http://localhost:1/tsl.xml"));
      assertThat(
              invoke(
                  tslProcurer,
                  "makeHashUrl",
                  Optional.class,
                  Optional.of("http://localhost:1/tsl.xml")))
          .isEqualTo(Optional.of("http://localhost:1/tsl.sha2"));
      assertThat(
              invoke(
                  tslProcurer,
                  "hasSameTslHash",
                  String.class,
                  String.class,
                  "same-hash",
                  "same-hash"))
          .isEqualTo(true);
      assertThat(
              invoke(
                  tslProcurer,
                  "hasSameTslHash",
                  String.class,
                  String.class,
                  "same-hash",
                  "other-hash"))
          .isEqualTo(false);
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldNotReinitializeTrustStoreWhenAlreadyInitialized() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();
    try {
      final Tsl originalTsl = new Tsl("old-hash", readSampleTsl());
      setField(tslProcurer, "currentTsl", originalTsl);
      setField(tslProcurer, "isInitialized", true);

      invoke(
          tslProcurer,
          "initializeEmptyTrustStore",
          String.class,
          byte[].class,
          "new-hash",
          readSampleTsl());

      assertThat(getField(tslProcurer, "currentTsl")).isSameAs(originalTsl);
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldInvalidateTrustStoreWhenTslValidityCheckFails() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();
    try (final MockedStatic<TucPki001Verifier> verifierMock = mockStatic(TucPki001Verifier.class)) {
      setField(tslProcurer, "currentTsl", new Tsl("hash", readSampleTsl()));
      setField(tslProcurer, "tspServiceTrustAnchor", mock(TspService.class));

      verifierMock
          .when(() -> TucPki001Verifier.verifyTslValidity(any(), anyInt(), any(), any()))
          .thenThrow(new GemPkiException("invalid", ErrorCode.TE_1006_TSL_DOWNLOAD_ERROR));

      assertThatThrownBy(() -> invoke(tslProcurer, "verifyTslValidity"))
          .hasCauseInstanceOf(TosException.class)
          .rootCause()
          .hasMessageContaining("invalid");

      assertThat(getField(tslProcurer, "currentTsl")).isNull();
      assertThat(getField(tslProcurer, "tspServiceTrustAnchor")).isNull();
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldHandleReceivedTslProcessingErrorsWithoutChangingCurrentTsl() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();
    try {
      final Tsl currentTsl = new Tsl("hash", readSampleTsl());
      setField(tslProcurer, "currentTsl", currentTsl);
      setField(tslProcurer, "tspServiceTrustAnchor", mock(TspService.class));

      invoke(
          tslProcurer,
          "processReceivedTsl",
          String.class,
          byte[].class,
          "new-hash",
          readSampleTsl());

      assertThat(getField(tslProcurer, "currentTsl")).isSameAs(currentTsl);
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldReturnEarlyWhenTrustStoreIsInvalidAfterInitialization() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();
    try {
      setField(tslProcurer, "isInitialized", true);
      setField(tslProcurer, "currentTsl", null);
      setField(tslProcurer, "tspServiceTrustAnchor", mock(TspService.class));

      invoke(tslProcurer, "processTslDownloadHttpResponse");

      assertThat(getField(tslProcurer, "currentTsl")).isNull();
    } finally {
      shutdown(tslProcurer);
    }
  }

  @Test
  void shouldShutdownExecutorOnExit() throws Exception {
    final TslProcurer tslProcurer = createTslProcurer();

    invoke(tslProcurer, "onExit");

    final ScheduledExecutorService executor =
        (ScheduledExecutorService) getField(tslProcurer, "scheduledExecutorServiceFetchTsl");
    assertThat(executor.isShutdown()).isTrue();
  }

  private TslProcurer createTslProcurer() {
    final TslProcurerProperties tslProcurerProperties = new TslProcurerProperties();
    tslProcurerProperties.setDownloadInterval(1);
    tslProcurerProperties.setTimeoutMilliseconds(100);
    tslProcurerProperties.setTslGracePeriodDays(0);

    final OcspProperties ocspProperties = new OcspProperties();
    ocspProperties.setOcspGracePeriodSeconds(30);
    ocspProperties.setOcspTimeoutSeconds(10);
    ocspProperties.setToleranceProducedAtPastSeconds(5);
    ocspProperties.setToleranceProducedAtFutureSeconds(3);

    return new TslProcurer(
        tslProcurerProperties, ocspProperties, new StaticTslSource("http://localhost:1/tsl.xml"));
  }

  private Object invoke(final Object target, final String methodName) throws Exception {
    final Method method = target.getClass().getDeclaredMethod(methodName);
    method.setAccessible(true);
    return method.invoke(target);
  }

  private Object invoke(
      final Object target,
      final String methodName,
      final Class<?> parameterType,
      final Object argument)
      throws Exception {
    final Method method = target.getClass().getDeclaredMethod(methodName, parameterType);
    method.setAccessible(true);
    return method.invoke(target, argument);
  }

  private Object invoke(
      final Object target,
      final String methodName,
      final Class<?> firstParameterType,
      final Class<?> secondParameterType,
      final Object firstArgument,
      final Object secondArgument)
      throws Exception {
    final Method method =
        target.getClass().getDeclaredMethod(methodName, firstParameterType, secondParameterType);
    method.setAccessible(true);
    return method.invoke(target, firstArgument, secondArgument);
  }

  private void setField(final Object target, final String fieldName, final Object value)
      throws Exception {
    final Field field = TslProcurer.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private Object getField(final Object target, final String fieldName) throws Exception {
    final Field field = TslProcurer.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(target);
  }

  private void shutdown(final TslProcurer tslProcurer) throws Exception {
    final Field field = TslProcurer.class.getDeclaredField("scheduledExecutorServiceFetchTsl");
    field.setAccessible(true);
    final ScheduledExecutorService executor = (ScheduledExecutorService) field.get(tslProcurer);
    if (executor != null) {
      executor.shutdownNow();
    }
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

  private record StaticTslSource(String url) implements TslSource {

    @Override
    public String getInitialTslUrl() {
      return url;
    }

    @Override
    public Optional<String> getPrimaryTslUrl(final Tsl currentTsl) {
      return Optional.of(url);
    }

    @Override
    public Optional<String> getBackupTslUrl(final Tsl currentTsl) {
      return Optional.of(url);
    }

    @Override
    public Optional<TslDownloadResults> downloadTslIfHashIsDifferent(final Tsl currentTsl) {
      return Optional.empty();
    }
  }
}
