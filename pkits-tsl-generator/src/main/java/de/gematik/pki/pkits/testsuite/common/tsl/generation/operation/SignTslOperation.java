/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import de.gematik.pki.gemlibpki.tsl.TslSigner;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import java.nio.file.Path;
import lombok.NonNull;
import org.w3c.dom.Document;

public class SignTslOperation implements TslOperation {

  @NonNull final Path tslSignerPath;
  @NonNull final String tslSignerPassword;
  final boolean signerKeyUsageCheck;
  final boolean signerValidityCheck;

  public SignTslOperation(
      @NonNull final Path tslSignerPath,
      @NonNull final String tslSignerPassword,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {
    this.tslSignerPath = tslSignerPath;
    this.tslSignerPassword = tslSignerPassword;
    this.signerKeyUsageCheck = signerKeyUsageCheck;
    this.signerValidityCheck = signerValidityCheck;
  }

  @Override
  public TslContainer apply(final TslContainer tslContainer) {

    final Document tslDoc = tslContainer.getAsTslDoc();

    final P12Container p12Container = P12Reader.getContentFromP12(tslSignerPath, tslSignerPassword);

    final TslSigner tslSigner =
        TslSigner.builder()
            .tslToSign(tslDoc)
            .tslSignerP12(p12Container)
            .checkSignerKeyUsage(signerKeyUsageCheck)
            .checkSignerValidity(signerValidityCheck)
            .build();

    tslSigner.sign();

    return new TslContainer(tslDoc);
  }
}
