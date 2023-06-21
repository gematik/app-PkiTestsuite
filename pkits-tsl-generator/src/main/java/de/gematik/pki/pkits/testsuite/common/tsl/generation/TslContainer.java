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

package de.gematik.pki.pkits.testsuite.common.tsl.generation;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import lombok.NonNull;
import org.w3c.dom.Document;

public class TslContainer {

  private TrustStatusListType tsl = null;
  private Document tslDoc = null;
  private byte[] tslBytes = null;

  public TslContainer(@NonNull final TslContainer tslContainer) {
    this.tsl = tslContainer.tsl;
    this.tslDoc = tslContainer.tslDoc;
    this.tslBytes = tslContainer.tslBytes;
  }

  public TslContainer(@NonNull final TrustStatusListType tsl) {
    this.tsl = tsl;
  }

  public TslContainer(@NonNull final Document tslDoc) {
    this.tslDoc = tslDoc;
  }

  public TslContainer(final byte @NonNull [] tslBytes) {
    this.tslBytes = tslBytes;
  }

  public TrustStatusListType getAsTsl() {
    if (tsl != null) {
      return tsl;
    } else if (tslBytes != null) {
      return TslConverter.bytesToTsl(tslBytes);
    }

    return TslConverter.bytesToTsl(TslConverter.docToBytes(tslDoc));
  }

  public Document getAsTslDoc() {
    if (tsl != null) {
      return TslConverter.tslToDoc(tsl);
    } else if (tslBytes != null) {
      return TslConverter.bytesToDoc(tslBytes);
    }
    return tslDoc;
  }

  public byte[] getAsTslBytes() {
    if (tsl != null) {
      return TslConverter.tslToBytes(tsl);
    } else if (tslBytes != null) {
      return tslBytes;
    }
    return TslConverter.docToBytes(tslDoc);
  }
}
