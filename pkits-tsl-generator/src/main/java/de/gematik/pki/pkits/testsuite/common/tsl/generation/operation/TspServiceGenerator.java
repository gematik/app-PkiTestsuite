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

import static de.gematik.pki.pkits.common.PkitsTestDataConstants.OCSP_SIGNER_RSA;

import de.gematik.pki.gemlibpki.certificate.CertificateType;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.exeptions.TslGenerationException;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import jakarta.xml.bind.JAXBElement;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import lombok.AllArgsConstructor;

public class TspServiceGenerator {

  private String serviceTypeIdentifier;
  private String serviceName;
  private boolean useServiceNameFromCert = true;
  private byte[] certificateBytes;
  private X509Certificate certificate;
  private String serviceStatus;
  private ZonedDateTime statusStartingTime;
  private String serviceSupplyPoint = "toBeDefined";
  private List<ServiceInformationExtension> serviceInformationExtensions;

  static ExtensionType toExtension(final CertificateType oid) {
    return toExtension(oid.getOid(), oid.getOidReference());
  }

  static ExtensionType toExtension(final String oid, final String oidValue) {
    final ExtensionType extension = new ExtensionType();
    extension.setCritical(false);

    final JAXBElement<?> extensionOidElem = createElem("ExtensionOID", oid);
    final JAXBElement<?> extensionValueElem = createElem("ExtensionValue", oidValue);

    extension.getContent().add(extensionOidElem);
    extension.getContent().add(extensionValueElem);

    return extension;
  }

  @AllArgsConstructor
  private static class ServiceInformationExtension {
    String oid;
    String reference;

    ExtensionType toExtension() {
      return TspServiceGenerator.toExtension(oid, reference);
    }
  }

  public TspServiceGenerator serviceTypeIdentifier(final String serviceTypeIdentifier) {
    this.serviceTypeIdentifier = serviceTypeIdentifier;
    return this;
  }

  public TspServiceGenerator serviceName(final String serviceName) {
    this.serviceName = serviceName;
    this.useServiceNameFromCert = false;
    return this;
  }

  public TspServiceGenerator certificate(final byte[] certificateBytes) {
    this.certificateBytes = certificateBytes;
    this.certificate = null;
    return this;
  }

  public TspServiceGenerator certificate(final X509Certificate certificate) {
    this.certificate = certificate;
    this.certificateBytes = null;
    return this;
  }

  public TspServiceGenerator serviceStatus(final String serviceStatus) {
    this.serviceStatus = serviceStatus;
    return this;
  }

  public TspServiceGenerator statusStartingTime(final ZonedDateTime statusStartingTime) {
    this.statusStartingTime = statusStartingTime;
    return this;
  }

  public TspServiceGenerator serviceSupplyPoint(final String serviceSupplyPoint) {
    this.serviceSupplyPoint = serviceSupplyPoint;
    return this;
  }

  public TspServiceGenerator addServiceInformationExtension(final CertificateType oid) {
    addServiceInformationExtension(oid.getOid(), oid.getOidReference());
    return this;
  }

  public TspServiceGenerator addServiceInformationExtension(
      final String oidValue, final String oidReference) {
    if (this.serviceInformationExtensions == null) {
      this.serviceInformationExtensions = new ArrayList<>();
    }
    this.serviceInformationExtensions.add(new ServiceInformationExtension(oidValue, oidReference));
    return this;
  }

  private static JAXBElement<?> createElem(final String elemName, final String elemValue) {
    return new JAXBElement<>(
        new QName("http://uri.etsi.org/02231/v2#", elemName), String.class, elemValue);
  }

  public TSPServiceType generate() {
    final TSPServiceType tspService = new TSPServiceType();

    final TSPServiceInformationType serviceInformation = new TSPServiceInformationType();
    tspService.setServiceInformation(serviceInformation);

    // -------------------------------
    serviceInformation.setServiceTypeIdentifier(serviceTypeIdentifier);
    final InternationalNamesType serviceNameContainerElem = new InternationalNamesType();

    final String serviceNameToUse;
    if (useServiceNameFromCert) {
      if (certificate == null) {
        throw new TslGenerationException(
            "Certificate is null, but expected to be provided!", new IllegalArgumentException());
      }
      serviceNameToUse = certificate.getSubjectX500Principal().getName();
    } else {
      serviceNameToUse = serviceName;
    }

    final MultiLangNormStringType serviceNameElem = new MultiLangNormStringType();
    serviceNameElem.setValue(serviceNameToUse);
    serviceNameElem.setLang("DE");

    serviceNameContainerElem.getName().add(serviceNameElem);
    serviceInformation.setServiceName(serviceNameContainerElem);
    // -------------------------------
    final DigitalIdentityListType digitalIdentityList = new DigitalIdentityListType();

    final DigitalIdentityType digitalIdentity = new DigitalIdentityType();
    byte[] certBytes = null;

    if (certificateBytes != null) {
      certBytes = certificateBytes;
    } else if (certificate != null) {
      certBytes = GemLibPkiUtils.certToBytes(certificate);
    }

    digitalIdentity.setX509Certificate(certBytes);

    digitalIdentityList.getDigitalId().add(digitalIdentity);
    serviceInformation.setServiceDigitalIdentity(digitalIdentityList);

    // -------------------------------
    serviceInformation.setServiceStatus(serviceStatus);

    if (statusStartingTime != null) {
      serviceInformation.setStatusStartingTime(
          TslModifier.getXmlGregorianCalendar(statusStartingTime));
    }

    // -------------------------------
    final ServiceSupplyPointsType serviceSupplyPoints = new ServiceSupplyPointsType();
    final AttributedNonEmptyURIType serviceSupplyPointElem = new AttributedNonEmptyURIType();
    serviceSupplyPointElem.setValue(serviceSupplyPoint);
    serviceSupplyPoints.getServiceSupplyPoint().add(serviceSupplyPointElem);
    serviceInformation.setServiceSupplyPoints(serviceSupplyPoints);

    // -------------------------------
    if (serviceInformationExtensions != null) {
      final ExtensionsListType extensions = new ExtensionsListType();
      serviceInformationExtensions.forEach(
          serviceInformationExtension ->
              extensions.getExtension().add(serviceInformationExtension.toExtension()));

      serviceInformation.setServiceInformationExtensions(extensions);
    }

    return tspService;
  }

  public static TSPServiceType getTspServiceKompCa() {
    return getTspServiceKomp(CertReader.readX509(PkitsTestDataConstants.DEFAULT_KOMP_CA));
  }

  public static TSPServiceType getTspServiceKompCaAlt() {
    return getTspServiceKomp(CertReader.readX509(PkitsTestDataConstants.ALTERNATIVE_KOMP_CA));
  }

  public static TSPServiceType getTspServiceKompCaRsa() {
    return getTspServiceKomp(CertReader.readX509(PkitsTestDataConstants.DEFAULT_KOMP_CA_RSA));
  }

  // OCSPSimulator-Signer-ecc.xml
  public static TSPServiceType getTspServiceOcspSigner() {
    return getTspServiceOcspSigner(PkitsTestDataConstants.DEFAULT_OCSP_SIGNER.getCertificate());
  }

  // OCSPSimulator-Signer.xml
  public static TSPServiceType getTspServiceOcspSignerRsa() {
    return getTspServiceOcspSigner(OCSP_SIGNER_RSA.getCertificate());
  }

  public static TSPServiceType getTspServiceSmcbCa() {
    return getTspServiceSmcb(CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA));
  }

  public static TSPServiceType getTspServiceSmcbCaAlt() {
    return getTspServiceSmcb(CertReader.readX509(PkitsTestDataConstants.ALTERNATIVE_SMCB_CA));
  }

  public static TSPServiceType getTspServiceSmcbCaRsa() {
    return getTspServiceSmcb(CertReader.readX509(PkitsTestDataConstants.DEFAULT_SMCB_CA_RSA));
  }

  public static TSPServiceType getTspServiceEgkCa() {
    return getTspServiceEgk(CertReader.readX509(PkitsTestDataConstants.DEFAULT_EGK_CA));
  }

  public static TSPServiceType getTspServiceEgkCaAlt() {
    return getTspServiceEgk(CertReader.readX509(PkitsTestDataConstants.ALTERNATIVE_EGK_CA));
  }

  public static TSPServiceType getTspServiceEgkCaRsa() {
    return getTspServiceEgk(CertReader.readX509(PkitsTestDataConstants.DEFAULT_EGK_CA_RSA));
  }

  public static TSPServiceType getTspServiceTslTrustAnchorCa() {
    return getStandardPkcTspServiceGenerator(PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR)
        .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
        .generate();
  }

  static TspServiceGenerator getStandardPkcTspServiceGenerator(final X509Certificate certificate) {
    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();

    return tspServiceGenerator
        .serviceTypeIdentifier(TslConstants.STI_PKC)
        .certificate(certificate)
        .serviceStatus(TslConstants.SVCSTATUS_INACCORD)
        .statusStartingTime(GemLibPkiUtils.now());
  }

  private static TSPServiceType getTspServiceKomp(final X509Certificate certificate) {

    return getStandardPkcTspServiceGenerator(certificate)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_AK_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_NK_VPN)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_SMKT_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_SAK_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_FD_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_ZD_TLS_S)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_FD_TLS_C)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_FD_TLS_S)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_CM_TLS_CS)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_FD_ENC)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_FD_SIG)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_SGD_HSM_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_ZD_SIG)
        .generate();
  }

  private static TSPServiceType getTspServiceOcspSigner(final X509Certificate certificate) {
    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();

    tspServiceGenerator
        .serviceTypeIdentifier(TslConstants.STI_OCSP)
        .certificate(certificate)
        .serviceStatus(TslConstants.SVCSTATUS_INACCORD)
        .statusStartingTime(GemLibPkiUtils.now())
        .serviceSupplyPoint("http://ocsp00.gematik.invalid/not-used")
        .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER);
    return tspServiceGenerator.generate();
  }

  private static TSPServiceType getTspServiceSmcb(final X509Certificate certificate) {
    return getStandardPkcTspServiceGenerator(certificate)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_SMC_B_ENC)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_SMC_B_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_SMC_B_OSIG)
        .generate();
  }

  private static TSPServiceType getTspServiceEgk(final X509Certificate certificate) {
    return getStandardPkcTspServiceGenerator(certificate)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_EGK_AUT)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_EGK_AUTN)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_EGK_ENC)
        .addServiceInformationExtension(CertificateType.CERT_TYPE_EGK_ENCV)
        .generate();
  }

  public static TSPServiceType getTspServiceUnspecifiedSti() {
    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();

    tspServiceGenerator
        .serviceTypeIdentifier(TslConstants.STI_UNSPECIFIED)
        .certificate(PkitsTestDataConstants.CERT_UNSPECIFIED_STI)
        .serviceStatus(TslConstants.SVCSTATUS_INACCORD)
        .statusStartingTime(GemLibPkiUtils.now())
        .serviceSupplyPoint("http://ocsp00.gematik.invalid/not-used")
        .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER);
    return tspServiceGenerator.generate();
  }

  public static TspServiceGenerator getTspServiceGeneratorTrustAnchorChange(
      final X509Certificate certificate) {
    final TspServiceGenerator tspServiceGenerator = new TspServiceGenerator();

    tspServiceGenerator
        .serviceTypeIdentifier(TslConstants.STI_SRV_CERT_CHANGE)
        .certificate(certificate)
        .serviceStatus(TslConstants.SVCSTATUS_INACCORD)
        .statusStartingTime(GemLibPkiUtils.now())
        .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_CCA_CERT);
    return tspServiceGenerator;
  }
}
