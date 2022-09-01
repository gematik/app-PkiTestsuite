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

import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.http.HttpStatus;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JsonTransceiver {

  public static void sendJsonViaHttp(final String uri, final String jsonContent) {
    try {
      final HttpResponse<String> response = Unirest.post(uri).body(jsonContent).asString();
      if (response.getStatus() != HttpStatus.SC_OK) {
        throw new PkiCommonException("Send failed with HttpStatus: " + response.getStatus());
      }
    } catch (final UnirestException e) {
      throw new PkiCommonException("Generation of request failed.", e);
    }
  }

  /**
   * Sends and receives JSON
   *
   * @param uri Receiver
   * @param jsonContent request body (JSON)
   * @return response body (JSON)
   */
  public static String txRxJsonViaHttp(final String uri, final String jsonContent) {
    try {
      final HttpResponse<String> response = Unirest.post(uri).body(jsonContent).asString();
      if (response.getStatus() != HttpStatus.SC_OK) {
        throw new PkiCommonException("Send failed with HttpStatus: " + response.getStatus());
      }
      return response.getBody();
    } catch (final UnirestException e) {
      throw new PkiCommonException("Generation of request failed.", e);
    }
  }
}
