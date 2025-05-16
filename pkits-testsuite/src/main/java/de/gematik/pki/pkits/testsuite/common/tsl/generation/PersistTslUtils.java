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

import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TslUtils;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.reporting.CurrentTestInfo;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PersistTslUtils {

  private static final String TSL_DIRNAME = "./out/tsl";
  private static final String TSL_FILENAME_PREFIX = "Tsl_";

  public static String getSignerCertIssuerCn(final TrustStatusListType tsl) {
    try {
      final X509Certificate signerCert = TslUtils.getFirstTslSignerCertificate(tsl);

      final X500Name x500name = new JcaX509CertificateHolder(signerCert).getIssuer();
      final RDN cnRdn = x500name.getRDNs(BCStyle.CN)[0];

      final String issuerCn = IETFUtils.valueToString(cnRdn.getFirst().getValue());

      return "_" + StringUtils.replace(issuerCn, " ", "_");

    } catch (final Exception e) {
      return "";
    }
  }

  public static Path generateTslFilename(
      final CurrentTestInfo currentTestInfo, final String tslName, final TrustStatusListType tsl) {
    final String extendedPostfix;

    final String tslNameToUse = StringUtils.isNotBlank(tslName) ? "__" + tslName : "";

    if (currentTestInfo != null) {

      final String trustAnchorIssuerCn = getSignerCertIssuerCn(tsl);

      extendedPostfix =
          "%s__%s%s_n%d%s%s"
              .formatted(
                  tsl.getId(),
                  currentTestInfo.getMethodName(),
                  currentTestInfo.getParameterizedIndexStr(),
                  currentTestInfo.getTslCounter(),
                  tslNameToUse,
                  trustAnchorIssuerCn);

      currentTestInfo.incrementTslCounter();
    } else {
      extendedPostfix = tsl.getId() + tslNameToUse;
    }

    return Path.of(
        TSL_DIRNAME,
        "%s%04d_%s.xml"
            .formatted(TSL_FILENAME_PREFIX, TslReader.getTslSeqNr(tsl), extendedPostfix));
  }

  public static void saveBytes(final Path tslFilePathToUse, final byte[] tslBytes) {

    try {
      if (Files.notExists(tslFilePathToUse.getParent())) {
        Files.createDirectories(tslFilePathToUse.getParent());
      }
      Files.write(tslFilePathToUse, tslBytes);
      log.info("saved TSL to file: {}", tslFilePathToUse);
    } catch (final IOException e) {
      throw new TestSuiteException("cannot save TSL to file", e);
    }
  }
}
