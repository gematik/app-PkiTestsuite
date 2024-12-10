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

package de.gematik.pki.pkits.sut.server.sim.tsl;

import kong.unirest.core.HttpResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;

@Slf4j
final class TslDownloadResults {

  final boolean failed;
  String hashValue = null;
  byte[] tslBytes = null;

  private TslDownloadResults(final boolean failed) {
    this.failed = failed;
  }

  static TslDownloadResults fail() {
    return new TslDownloadResults(true);
  }

  static TslDownloadResults forHash(final HttpResponse<String> httpResponse) {

    log.debug("forHash httpResponse.getStatus() {}", httpResponse.getStatus());
    if (httpResponse.getStatus() == HttpStatus.SC_OK) {
      final TslDownloadResults tslDownloadResults = new TslDownloadResults(false);
      tslDownloadResults.hashValue = httpResponse.getBody();
      return tslDownloadResults;
    } else {
      if (httpResponse.getBody() != null) {
        log.info("{}", httpResponse.getBody());
      }
    }
    return TslDownloadResults.fail();
  }

  static TslDownloadResults forTslBytes(final HttpResponse<byte[]> httpResponse) {

    if (httpResponse.getStatus() == HttpStatus.SC_OK) {
      final TslDownloadResults tslDownloadResults = new TslDownloadResults(false);
      tslDownloadResults.tslBytes = httpResponse.getBody();

      if (!((tslDownloadResults.tslBytes == null) || (tslDownloadResults.tslBytes.length == 0))) {
        return tslDownloadResults;
      }
    }

    return TslDownloadResults.fail();
  }

  @Override
  public String toString() {

    final String tslBytesInfo = (tslBytes == null) ? "=null" : (".length=" + tslBytes.length);
    return "TslDownloadResults{failed=%s, hashValue='%s', tslBytes%s}"
        .formatted(failed, hashValue, tslBytesInfo);
  }
}
