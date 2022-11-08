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

package de.gematik.pki.pkits.testsuite.common.tsl;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TslSigner;
import de.gematik.pki.gemlibpki.utils.GemlibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.pkits.common.PkiCommonException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import org.w3c.dom.Document;

public abstract class TslGeneration {

  public static byte[] createTslFromFile(
      @NonNull final Path tslPath,
      @NonNull final TslModification tslMod,
      @NonNull final Path tslSignerPath,
      @NonNull final String tslSignerPassword)
      throws DatatypeConfigurationException {
    final TrustStatusListType tslT = TslReader.getTsl(tslPath).orElseThrow();
    modifyTsl(tslT, tslMod);
    final Document tslDoc = TslConverter.tslToDoc(tslT).orElseThrow();
    final P12Container signer =
        P12Reader.getContentFromP12(GemlibPkiUtils.readContent(tslSignerPath), tslSignerPassword);
    TslSigner.sign(tslDoc, signer);
    return TslConverter.docToBytes(tslDoc).orElseThrow();
  }

  private static void modifyTsl(
      @NonNull final TrustStatusListType tslT, @NonNull final TslModification tslMod)
      throws DatatypeConfigurationException {
    if (tslMod.getNextUpdate() == null) {
      if (tslMod.getDaysUntilNextUpdate() <= 0) {
        throw new PkiCommonException(
            "TslModification must contain nextUpdate or daysUntilNextUpdate.");
      } else {
        TslModifier.modifyIssueDateAndRelatedNextUpdate(
            tslT, tslMod.getIssueDate(), tslMod.getDaysUntilNextUpdate());
      }
    } else {
      TslModifier.modifyIssueDate(tslT, tslMod.getIssueDate());
      TslModifier.modifyNextUpdate(tslT, tslMod.getNextUpdate());
    }

    tslT.setId(TslModifier.generateTslId(tslMod.getSequenceNr(), tslMod.getIssueDate()));
    // TODO count number of modified entries and log.debug them
    TslModifier.modifySequenceNr(tslT, tslMod.getSequenceNr());
    TslModifier.modifySspForCAsOfTsp(tslT, tslMod.getTspName(), tslMod.getNewSsp());
    TslModifier.modifyTslDownloadUrlPrimary(tslT, tslMod.getTslDownloadUrlPrimary());
    TslModifier.modifyTslDownloadUrlBackup(tslT, tslMod.getTslDownloadUrlBackup());
  }
}
