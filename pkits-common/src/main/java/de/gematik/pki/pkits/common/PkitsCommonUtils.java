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

package de.gematik.pki.pkits.common;

import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.ResourceReader;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.CollectionType;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkitsCommonUtils {

  private static final String BUILD_INFO_RESOURCE = "/META-INF/build-info.properties";
  private static final String DEFAULT_IMPLEMENTATION_VERSION = "unknown";

  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS");

  public static String asTimestampStr(final ZonedDateTime dateTime) {
    return dateTime.format(dateTimeFormatter);
  }

  public static String getHttpAddressString(final String ipAddressOrFqdn, final int port) {
    return "http://" + ipAddressOrFqdn + ":" + port;
  }

  public static boolean isExternalStartup(final String appPath) {
    return PkitsConstants.EXTERNAL_STARTUP.equals(appPath);
  }

  public static String calculateSha256Hex(final byte[] byteArray) {
    final byte[] hash = GemLibPkiUtils.calculateSha256(byteArray);
    return new String(Hex.encode(hash), StandardCharsets.UTF_8);
  }

  public static void waitSeconds(final long seconds) {
    waitMilliseconds(seconds * 1000);
  }

  public static void waitMilliseconds(final long milliseconds) {

    try {
      log.info("Waiting for {} milliseconds.", milliseconds);
      final ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
      executorService.schedule(() -> 0, milliseconds, TimeUnit.MILLISECONDS).get();
      executorService.shutdown();
    } catch (final InterruptedException | ExecutionException e) {
      Thread.currentThread().interrupt();
      throw new PkiCommonException("Problems in waitMilliseconds", e);
    }
  }

  public static String createJsonContent(final Object infoReq) {
    try {
      return JsonMapper.builder().build().writeValueAsString(infoReq);
    } catch (final JacksonException e) {
      throw new PkiCommonException("Generation of JsonContent failed.", e);
    }
  }

  public static <T> List<T> convertToList(final String jsonStr, final Class<T> clazz) {
    try {
      final JsonMapper mapper = JsonMapper.builder().build();
      final CollectionType type =
          mapper.getTypeFactory().constructCollectionType(List.class, clazz);

      return mapper.readValue(jsonStr, type);

    } catch (final JacksonException e) {
      throw new PkiCommonException("Deserialization of json string failed.", e);
    }
  }

  public static void checkHealth(
      final Logger log, final String serviceNameForMessage, final String uri) {
    try {
      final HttpResponse<String> response =
          Unirest.get(uri + PkitsConstants.WEBSERVER_HEALTH_ENDPOINT).asString();
      final int responseHttpStatus = response.getStatus();
      if (responseHttpStatus != HttpStatus.SC_OK) {
        throw new PkiCommonException(
            "health request to %s returned with: %d"
                .formatted(serviceNameForMessage, responseHttpStatus));
      }
    } catch (final UnirestException e) {
      throw new PkiCommonException("%s has health problem".formatted(serviceNameForMessage), e);
    }
    log.debug("{} health ok", serviceNameForMessage);
  }

  public static String getFirstSubStringByPattern(final String src, final String searchPattern) {
    String ret = "";
    final Pattern pattern = Pattern.compile(searchPattern);
    final Matcher matcher = pattern.matcher(src);

    if (matcher.find()) {
      ret = matcher.group(1);
    }
    return ret;
  }

  public static Attributes readManifestAttributes(final Class<?> clazz) {
    final ClassLoader classLoader = clazz.getClassLoader();
    final String manifestFilename = "META-INF/MANIFEST.MF";
    final URL url = classLoader.getResource(manifestFilename);
    if (url == null) {
      throw new PkiCommonException("cannot find " + manifestFilename);
    }
    try {
      final InputStream inputStream = url.openStream();
      final Manifest manifest = new Manifest(inputStream);
      return manifest.getMainAttributes();
    } catch (final IOException e) {
      throw new PkiCommonException("cannot process " + manifestFilename, e);
    }
  }

  public static String getBannerStr(final Class<?> clazz, final String filename) {
    final String bannerFormat = ResourceReader.getFileFromResourceAsString(filename, clazz);
    final String version = readBuildVersion(clazz);

    return bannerFormat.formatted(version);
  }

  static String readBuildVersion(final Class<?> clazz) {
    final Properties properties = new Properties();
    try (final InputStream inputStream = clazz.getResourceAsStream(BUILD_INFO_RESOURCE)) {
      if (inputStream != null) {
        properties.load(inputStream);
      }
    } catch (final IOException e) {
      log.debug("Unable to read {}", BUILD_INFO_RESOURCE, e);
    }

    final String value = properties.getProperty("build.version");
    if (value == null) {
      return DEFAULT_IMPLEMENTATION_VERSION;
    }

    final String trimmedValue = value.trim();
    return trimmedValue.isEmpty() ? DEFAULT_IMPLEMENTATION_VERSION : trimmedValue;
  }

  public static String toUpperHex(final BigInteger value) {
    if (value == null) {
      return "null";
    }
    String hex = value.toString(16).toUpperCase(Locale.ROOT);
    if ((hex.length() & 1) == 1) {
      hex = "0" + hex;
    }
    return hex;
  }
}
