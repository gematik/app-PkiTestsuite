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

package de.gematik.pki.pkits.common;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ResourceReader {

  public static byte[] getFileFromResourceAsBytes(final String file) {
    try {
      return Objects.requireNonNull(ResourceReader.class.getClassLoader().getResourceAsStream(file))
          .readAllBytes();
    } catch (final NullPointerException | IOException e) {
      throw new PkiCommonException("Error reading resource: " + file, e);
    }
  }

  public static String getFileFromResourceAsString(final String filename) {
    return new String(getFileFromResourceAsBytes(filename), StandardCharsets.UTF_8);
  }
}
