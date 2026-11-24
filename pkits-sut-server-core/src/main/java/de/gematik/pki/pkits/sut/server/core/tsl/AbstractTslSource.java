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

import de.gematik.pki.pkits.sut.server.core.configs.TslProcurerProperties;
import java.util.Optional;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
abstract class AbstractTslSource implements TslSource {

  protected final TslProcurerProperties tslProcurerProperties;

  @Override
  public Optional<TslDownloadResults> downloadTslIfHashIsDifferent(final Tsl currentTsl) {
    final boolean hasBackup = hasBackupTslUrl();
    final Optional<String> primaryUrl = getPrimaryTslUrl(currentTsl);
    final Optional<String> backupUrl = hasBackup ? getBackupTslUrl(currentTsl) : Optional.empty();

    if (hasSameHash(primaryUrl, backupUrl, currentTsl)) {
      log.info(
          "No TSL download required, since hash value was not changed - {} (current tslSeqNr {})",
          currentTsl.tslHash,
          currentTsl.tslSeqNr);
      return Optional.empty();
    }

    final int maxAttempts = hasBackup ? 8 : 4;
    for (int i = 0; i < maxAttempts; ++i) {
      final Optional<String> urlToUseOpt;
      final String urlType;
      if (i < 4) {
        urlToUseOpt = primaryUrl;
        urlType = "Primary";
      } else {
        urlToUseOpt = backupUrl;
        urlType = "Backup ";
      }

      final TslDownloadResults tslDownloadResults;
      if (urlToUseOpt.isPresent()) {
        tslDownloadResults =
            downloadTsl(urlToUseOpt.get(), "%s, attempt count=%d.".formatted(urlType, i + 1));
      } else {
        log.info("{}, attempt count={} is SKIPPED as the URL is undefined.", urlType, i + 1);
        tslDownloadResults = TslDownloadResults.fail();
      }

      if (!tslDownloadResults.failed) {
        log.info("Successful TSL download after {} attempts.", i + 1);
        return Optional.of(tslDownloadResults);
      }
    }

    return Optional.empty();
  }

  protected boolean hasBackupTslUrl() {
    return true;
  }

  private TslDownloadResults downloadTsl(final String tslUrl, final String additionalInfo) {
    log.info("{}: downloading TSL at: {}", additionalInfo, tslUrl);
    try {
      Unirest.config().reset().connectTimeout(tslProcurerProperties.getTimeoutMilliseconds());
      final HttpResponse<byte[]> bytesResponse = Unirest.get(tslUrl).asBytes();
      return TslDownloadResults.forTslBytes(bytesResponse);
    } catch (final UnirestException e) {
      log.info("Downloading TSL failed. {}", e.getMessage());
    }

    return TslDownloadResults.fail();
  }

  private boolean hasSameHash(
      final Optional<String> tslPrimaryUrl,
      final Optional<String> tslBackupUrl,
      final Tsl currentTsl) {
    final Optional<String> hashPrimaryUrl = makeHashUrl(tslPrimaryUrl);
    final Optional<String> hashBackupUrl = makeHashUrl(tslBackupUrl);

    TslDownloadResults hashTslDownloadResults =
        hashPrimaryUrl.isPresent()
            ? downloadTslHash(hashPrimaryUrl.get())
            : TslDownloadResults.fail();

    if (hashTslDownloadResults.failed) {
      hashTslDownloadResults =
          hashBackupUrl.isPresent()
              ? downloadTslHash(hashBackupUrl.get())
              : TslDownloadResults.fail();
    }

    if (hashTslDownloadResults.failed) {
      return false;
    }

    return hasSameTslHash(currentTsl.tslHash, hashTslDownloadResults.hashValue);
  }

  private Optional<String> makeHashUrl(final Optional<String> tslDownloadUrl) {
    return tslDownloadUrl.map(s -> s.replace(".xml", ".sha2"));
  }

  private TslDownloadResults downloadTslHash(@NonNull final String hashUrl) {
    try {
      Unirest.config().reset().connectTimeout(tslProcurerProperties.getTimeoutMilliseconds());
      final HttpResponse<String> stringHttpResponse = Unirest.get(hashUrl).asString();
      return TslDownloadResults.forHash(stringHttpResponse);
    } catch (final UnirestException e) {
      log.info("Downloading TSL HASH failed. {}", e.getMessage());
    }

    return TslDownloadResults.fail();
  }

  private boolean hasSameTslHash(
      @NonNull final String hashValueLocal, @NonNull final String hashValueOnline) {
    log.info("Comparing TSL hash: local ({}) vs. online ({})", hashValueLocal, hashValueOnline);
    return hashValueOnline.equals(hashValueLocal);
  }
}
