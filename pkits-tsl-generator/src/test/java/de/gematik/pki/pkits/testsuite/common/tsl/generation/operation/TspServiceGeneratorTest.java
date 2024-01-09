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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.certificate.CertificateType;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.exeptions.TslGenerationException;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import jakarta.xml.bind.JAXBElement;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class TspServiceGeneratorTest {

  final String getExtensionElementContent(
      final TSPServiceType tspService, final int extensionIndex, final int elementContentIndex) {
    final List<Object> content =
        tspService
            .getServiceInformation()
            .getServiceInformationExtensions()
            .getExtension()
            .get(extensionIndex)
            .getContent();

    final JAXBElement<?> node = (JAXBElement<?>) content.get(elementContentIndex);
    return (String) node.getValue();
  }

  @Test
  void testToExtension() {
    final CertificateType certificateType = CertificateType.CERT_TYPE_SMC_B_AUT;
    final ExtensionType extensionType = TspServiceGenerator.toExtension(certificateType);

    assertThat(extensionType.isCritical()).isFalse();
    final List<Object> content = extensionType.getContent();

    final JAXBElement<?> elem1 = ((JAXBElement<?>) content.get(0));
    assertThat(elem1.getValue()).isEqualTo(certificateType.getOid());

    final JAXBElement<?> elem2 = ((JAXBElement<?>) content.get(1));
    assertThat(elem2.getValue()).isEqualTo(certificateType.getOidReference());
  }

  @Test
  void testGenerate() throws CertificateEncodingException {

    final X509Certificate certificate =
        CertReader.readX509(PkitsTestDataConstants.ALTERNATIVE_KOMP_CA);

    final String serviceName = "serviceName1";
    final String serviceStatus = "serviceStatus1";
    final String serviceTypeIdentifier = "serviceTypeIdentifier1";

    final ZonedDateTime now = GemLibPkiUtils.now();

    final String oidValue = "oidValue1";
    final String oidName = "oidName1";

    final CertificateType certTypeOid = CertificateType.CERT_TYPE_SMC_B_AUT;

    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();
    final TSPServiceType tspService =
        tspServiceGenerator
            .certificate(certificate)
            .serviceName(serviceName)
            .serviceStatus(serviceStatus)
            .serviceTypeIdentifier(serviceTypeIdentifier)
            .statusStartingTime(now)
            .addServiceInformationExtension(oidValue, oidName)
            .addServiceInformationExtension(certTypeOid)
            .generate();

    final byte[] certBytes =
        tspService
            .getServiceInformation()
            .getServiceDigitalIdentity()
            .getDigitalId()
            .get(0)
            .getX509Certificate();

    Assertions.assertThat(certBytes).isEqualTo(certificate.getEncoded());

    Assertions.assertThat(
            tspService.getServiceInformation().getServiceName().getName().get(0).getValue())
        .isEqualTo(serviceName);

    Assertions.assertThat(tspService.getServiceInformation().getServiceStatus())
        .isEqualTo(serviceStatus);

    Assertions.assertThat(tspService.getServiceInformation().getServiceTypeIdentifier())
        .isEqualTo(serviceTypeIdentifier);

    Assertions.assertThat(tspService.getServiceInformation().getStatusStartingTime())
        .isEqualTo(TslModifier.getXmlGregorianCalendar(now));

    Assertions.assertThat(
            tspService
                .getServiceInformation()
                .getServiceInformationExtensions()
                .getExtension()
                .get(0)
                .isCritical())
        .isFalse();

    Assertions.assertThat(getExtensionElementContent(tspService, 0, 0)).isEqualTo(oidValue);
    Assertions.assertThat(getExtensionElementContent(tspService, 0, 1)).isEqualTo(oidName);

    Assertions.assertThat(getExtensionElementContent(tspService, 1, 0))
        .isEqualTo(certTypeOid.getOid());
    Assertions.assertThat(getExtensionElementContent(tspService, 1, 1))
        .isEqualTo(certTypeOid.getOidReference());
  }

  @Test
  void testGenerateWithCertBytes() {

    final byte[] certBytes = "dummyCertBytes".getBytes();

    final String serviceName = "serviceName1";
    final String serviceStatus = "serviceStatus1";
    final String serviceTypeIdentifier = "serviceTypeIdentifier1";

    final ZonedDateTime now = GemLibPkiUtils.now();

    final String oidValue = "oidValue1";
    final String oidName = "oidName1";

    final CertificateType certTypeOid = CertificateType.CERT_TYPE_SMC_B_AUT;

    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();
    final TSPServiceType tspService =
        tspServiceGenerator
            .certificate(certBytes)
            .serviceName(serviceName)
            .serviceStatus(serviceStatus)
            .serviceTypeIdentifier(serviceTypeIdentifier)
            .statusStartingTime(now)
            .addServiceInformationExtension(oidValue, oidName)
            .addServiceInformationExtension(certTypeOid)
            .generate();

    assertThat(
            tspService
                .getServiceInformation()
                .getServiceDigitalIdentity()
                .getDigitalId()
                .get(0)
                .getX509Certificate())
        .isEqualTo(certBytes);
  }

  @Test
  void testGenerateException() {

    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();

    assertThatThrownBy(tspServiceGenerator::generate)
        .isInstanceOf(TslGenerationException.class)
        .hasMessage("Certificate is null, but expected to be provided!");
  }

  @Test
  void testGenerateServiceName() {

    final X509Certificate certificate =
        CertReader.readX509(PkitsTestDataConstants.ALTERNATIVE_KOMP_CA);

    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();
    final TSPServiceType tspService = tspServiceGenerator.certificate(certificate).generate();

    Assertions.assertThat(
            tspService.getServiceInformation().getServiceName().getName().get(0).getValue())
        .isEqualTo(certificate.getSubjectX500Principal().getName());
  }
}
