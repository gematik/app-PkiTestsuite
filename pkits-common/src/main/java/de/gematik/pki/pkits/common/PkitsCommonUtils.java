/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.pki.pkits.common;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_HEALTH_ENDPOINT;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.http.HttpStatus;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkitsCommonUtils {

  public static boolean isExternalStartup(final String appPath) {
    return PkitsConstants.EXTERNAL_STARTUP.equals(appPath);
  }

  public static String calculateSha256Hex(final byte[] byteArray) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] hash = digest.digest(byteArray);
      return new String(Hex.encode(hash), StandardCharsets.UTF_8);
    } catch (final NoSuchAlgorithmException e) {
      throw new PkiCommonException("Instantiation of Digest object failed.", e);
    }
  }

  public static byte[] readContent(final String path) {
    return GemLibPkiUtils.readContent(Path.of(path));
  }

  public static void waitSeconds(final long seconds) {
    waitMilliseconds(seconds * 1000);
  }

  public static void waitMilliseconds(final long milliseconds) {

    try {
      final ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
      executorService.schedule(() -> 0, milliseconds, TimeUnit.MILLISECONDS).get();
    } catch (final InterruptedException | ExecutionException e) {
      Thread.currentThread().interrupt();
      throw new PkiCommonException("Problems in waitMilliseconds", e);
    }
  }

  public static String createJsonContent(final Object infoReq) {
    try {
      return new ObjectMapper().writeValueAsString(infoReq);
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

  public static Object bytesToObject(final byte[] bytes) {
    try (final ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        final ObjectInputStream ois = new ObjectInputStream(bais)) {
      return ois.readObject();
    } catch (final IOException | ClassNotFoundException e) {
      throw new PkiCommonException("Error deserializing byte[] to Object", e);
    }
  }

  public static byte[] objectToBytes(final Serializable obj) {
    try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final ObjectOutputStream os = new ObjectOutputStream(baos)) {
      os.flush();
      os.writeObject(obj);
      baos.flush();
      return baos.toByteArray();
    } catch (final IOException e) {
      throw new PkiCommonException("Error serializing object to byte[]", e);
    }
  }

  public static void checkHealth(
      final Logger log, final String serviceNameForMessage, final String uri) {
    try {
      final HttpResponse<String> response = Unirest.get(uri + WEBSERVER_HEALTH_ENDPOINT).asString();
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
}
