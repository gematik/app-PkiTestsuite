/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.testsuite.common.tsl.generation;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import lombok.NonNull;
import org.w3c.dom.Document;

public class TslContainer {

  private TrustStatusListType tslUnsigned = null;
  private Document tslDoc = null;
  private byte[] tslBytes = null;

  public TslContainer(@NonNull final TslContainer tslContainer) {
    this.tslUnsigned = tslContainer.tslUnsigned;
    this.tslDoc = tslContainer.tslDoc;
    this.tslBytes = tslContainer.tslBytes;
  }

  public TslContainer(@NonNull final TrustStatusListType tslUnsigned) {
    this.tslUnsigned = tslUnsigned;
  }

  public TslContainer(@NonNull final Document tslDoc) {
    this.tslDoc = tslDoc;
  }

  public TslContainer(final byte @NonNull [] tslBytes) {
    this.tslBytes = tslBytes;
  }

  public TrustStatusListType getAsTslUnsigned() {
    if (tslUnsigned != null) {
      return tslUnsigned;
    } else if (tslBytes != null) {
      return TslConverter.bytesToTslUnsigned(tslBytes);
    }

    return TslConverter.bytesToTslUnsigned(TslConverter.docToBytes(tslDoc));
  }

  public Document getAsTslUnsignedDoc() {
    if (tslUnsigned != null) {
      return TslConverter.tslToDocUnsigned(tslUnsigned);
    } else if (tslBytes != null) {
      return TslConverter.bytesToDoc(tslBytes);
    }
    return tslDoc;
  }

  public byte[] getAsTslUnsignedBytes() {
    if (tslUnsigned != null) {
      return TslConverter.tslUnsignedToBytes(tslUnsigned);
    } else if (tslBytes != null) {
      return tslBytes;
    }
    return TslConverter.docToBytes(tslDoc);
  }
}
