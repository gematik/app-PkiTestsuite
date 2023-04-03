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

package de.gematik.pki.pkits.testsuite.unittests;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TslSigner;
import de.gematik.pki.gemlibpki.tsl.TslWriter;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import javax.xml.datatype.DatatypeConfigurationException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslNextUpdate {

  @Disabled
  @Test
  void setNextUpdate() throws DatatypeConfigurationException {

    final Path inputTslPath = Path.of("./testDataTemplates/tsl/TSL_default.xml");
    final Path outputTslPath = Path.of("./testDataTemplates/tsl/TSL_default_new_nextUpdate.xml");

    final TrustStatusListType tsl = TslReader.getTsl(inputTslPath);
    final Path signerCertPath =
        Path.of(
            "./testDataTemplates/certificates/ecc/trustAnchor/TSL-Signing-Unit-8-TEST-ONLY.p12");

    final P12Container signerEcc = P12Reader.getContentFromP12(signerCertPath, "00");

    final ZonedDateTime newDate = GemLibPkiUtils.now().plus(6, ChronoUnit.MONTHS);

    TslModifier.modifyNextUpdate(tsl, newDate);

    final Document tslDoc = TslConverter.tslToDoc(tsl);

    final TslSigner tslSigner =
        TslSigner.builder().tslToSign(tslDoc).tslSignerP12(signerEcc).build();

    tslSigner.sign();

    TslWriter.write(tslDoc, outputTslPath);
  }
}
