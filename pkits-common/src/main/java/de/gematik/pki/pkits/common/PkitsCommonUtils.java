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

package de.gematik.pki.pkits.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.Attributes.Name;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkitsCommonUtils {

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
    } catch (final InterruptedException | ExecutionException e) {
      Thread.currentThread().interrupt();
      throw new PkiCommonException("Problems in waitMilliseconds", e);
    }
  }

  public static String createJsonContent(final Object infoReq) {
    try {
      return new ObjectMapper().registerModule(new JavaTimeModule()).writeValueAsString(infoReq);
    } catch (final JsonProcessingException e) {
      throw new PkiCommonException("Generation of JsonContent failed.", e);
    }
  }

  public static <T> List<T> convertToList(final String jsonStr, final Class<T> clazz) {
    try {
      final ObjectMapper mapper = new ObjectMapper();
      final JavaType type = mapper.getTypeFactory().constructCollectionType(List.class, clazz);

      return mapper.readValue(jsonStr, type);

    } catch (final JsonProcessingException e) {
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

  @Getter
  @ToString
  public static class GitProperties {

    private String commitIdShort = "not-defined";
    private String commitIdFull = "not-defined";

    public GitProperties() {}

    public GitProperties(final Properties prop) {
      commitIdShort = prop.getProperty("git.commit.id.abbrev");
      commitIdFull = prop.getProperty("git.commit.id.full");
    }
  }

  public static GitProperties readGitProperties(final Class<?> clazz) {
    final Properties props = new Properties();
    final String gitPropsFilename = "git.properties";
    try {
      // load a properties file from class path, inside static method
      props.load(clazz.getClassLoader().getResourceAsStream(gitPropsFilename));

      return new GitProperties(props);

    } catch (final NullPointerException | IOException e) {
      log.warn("continue: cannot read {} - {}", gitPropsFilename, e.getMessage());
      return new GitProperties();
    }
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
    final Attributes attributes = PkitsCommonUtils.readManifestAttributes(clazz);

    final String bannerFormat = ResourceReader.getFileFromResourceAsString(filename, clazz);
    final String title = attributes.getValue(Name.IMPLEMENTATION_TITLE);
    final String version = attributes.getValue(Name.IMPLEMENTATION_VERSION);
    final String springBootVersion = attributes.getValue("Spring-Boot-Version");

    final GitProperties gitProperties = PkitsCommonUtils.readGitProperties(clazz);

    return bannerFormat.formatted(
        title, version, gitProperties.getCommitIdShort(), springBootVersion);
  }
}
