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

package de.gematik.pki.pkits.testsuite.common.tsl;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TslSigner;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import org.w3c.dom.Document;

public abstract class TslGeneration {

  public static byte[] signTslDoc(
      final Document tslDoc,
      @NonNull final Path tslSignerPath,
      @NonNull final String tslSignerPassword,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck) {

    final P12Container p12Container = P12Reader.getContentFromP12(tslSignerPath, tslSignerPassword);

    TslSigner.builder()
        .tslToSign(tslDoc)
        .tslSignerP12(p12Container)
        .checkSignerKeyUsage(signerKeyUsageCheck)
        .checkSignerValidity(signerValidityCheck)
        .build()
        .sign();

    return TslConverter.docToBytes(tslDoc);
  }

  public static byte[] createTslFromFile(
      @NonNull final Path tslTemplate,
      @NonNull final TslModification tslModification,
      @NonNull final Path tslSignerPath,
      @NonNull final String tslSignerPassword,
      final boolean signerKeyUsageCheck,
      final boolean signerValidityCheck)
      throws DatatypeConfigurationException {

    final TrustStatusListType tsl = TslReader.getTsl(tslTemplate);

    tslModification.modify(tsl);

    final Document tslDoc = TslConverter.tslToDoc(tsl);

    return signTslDoc(
        tslDoc, tslSignerPath, tslSignerPassword, signerKeyUsageCheck, signerValidityCheck);
  }
}
