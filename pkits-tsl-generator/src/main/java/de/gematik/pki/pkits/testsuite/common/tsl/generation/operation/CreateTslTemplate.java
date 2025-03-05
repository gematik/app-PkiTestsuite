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

import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TspServiceGenerator.getTspServiceGeneratorTrustAnchorChange;

import de.gematik.pki.gemlibpki.certificate.CertificateType;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
import de.gematik.pki.pkits.common.PkitsTestDataConstants;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.TslContainer;
import de.gematik.pki.pkits.testsuite.common.tsl.generation.exeptions.TslGenerationException;
import eu.europa.esig.trustedlist.jaxb.tsl.AddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.ElectronicAddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionsListType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.PostalAddressListType;
import eu.europa.esig.trustedlist.jaxb.tsl.PostalAddressType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.datatype.XMLGregorianCalendar;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CreateTslTemplate {

  public static final Path ARVATO_TU_TSL = Path.of("./testDataTemplates/tsl/ECC-RSA_TSL-test.xml");

  public static final Path ARVATO_TU_ECC_ONLY_TSL =
      Path.of("./testDataTemplates/tsl/ECC_TSL-test.xml");

  static final String ARVATO_TSL_CERT_TSL_CA28_SHA256 =
      "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a";
  public static final String ARVATO_TSL_OCSP_SIGNER_10_CERT_SHA256 =
      "570026f5fa80b05454bbf6eb5480a02140a58911cb128392c773240d36186062";

  static List<TSPServiceType> combined(
      final List<TSPServiceType> list, final TSPServiceType... tspServices) {
    return combined(list, Arrays.asList(tspServices));
  }

  @SafeVarargs
  static List<TSPServiceType> combined(final List<TSPServiceType>... lists) {
    final List<TSPServiceType> tspServices = new ArrayList<>();
    for (final List<TSPServiceType> list : lists) {
      tspServices.addAll(list);
    }
    return tspServices;
  }

  static TSPInformationType getStandardTspInformation() {

    final String LANG_DE = "DE";

    final TSPInformationType tspInformation = new TSPInformationType();

    tspInformation.setTSPName(new InternationalNamesType());

    final MultiLangNormStringType tspName = new MultiLangNormStringType();

    tspName.setLang(LANG_DE);
    tspName.setValue(PkitsConstants.GEMATIK_TEST_TSP);

    tspInformation.getTSPName().getName().add(tspName);
    // -----------------------------------------------------------------

    tspInformation.setTSPTradeName(new InternationalNamesType());
    final MultiLangNormStringType tspTradeName = new MultiLangNormStringType();
    tspTradeName.setLang(LANG_DE);
    tspTradeName.setValue(PkitsConstants.GEMATIK_TEST_TSP_TRADENAME);
    tspInformation.getTSPTradeName().getName().add(tspTradeName);
    // -----------------------------------------------------------------

    tspInformation.setTSPAddress(new AddressType());
    tspInformation.getTSPAddress().setPostalAddresses(new PostalAddressListType());

    final PostalAddressType postalAddress = new PostalAddressType();
    postalAddress.setLang(LANG_DE);
    postalAddress.setStreetAddress("Friedrichstrasse 136");
    postalAddress.setLocality("Berlin");
    postalAddress.setPostalCode("10117");
    postalAddress.setCountryName("DE");

    tspInformation.getTSPAddress().getPostalAddresses().getPostalAddress().add(postalAddress);
    // -----------------------------------------------------------------

    tspInformation.getTSPAddress().setElectronicAddress(new ElectronicAddressType());
    final NonEmptyMultiLangURIType emailUri = new NonEmptyMultiLangURIType();
    emailUri.setValue(PkitsConstants.GEMATIK_PKI_EMAIL_URI);
    tspInformation.getTSPAddress().getElectronicAddress().getURI().add(emailUri);
    // -----------------------------------------------------------------

    tspInformation.setTSPInformationURI(new NonEmptyMultiLangURIListType());
    final NonEmptyMultiLangURIType uri = new NonEmptyMultiLangURIType();
    uri.setValue("http://www.gematik.de");
    uri.setLang(LANG_DE);
    tspInformation.getTSPInformationURI().getURI().add(uri);

    return tspInformation;
  }

  private static List<TSPServiceType> getDefaultTspServices(final boolean eccOnly) {
    if (eccOnly) {
      return getCommonTspServices();
    }
    return combined(
        List.of(
            TspServiceGenerator.getTspServiceKompCaRsa(),
            TspServiceGenerator.getTspServiceSmcbCaRsa(),
            TspServiceGenerator.getTspServiceEgkCaRsa(),
            TspServiceGenerator.getTspServiceOcspSignerRsa()),
        getCommonTspServices());
  }

  private static List<TSPServiceType> getCommonTspServices() {
    return List.of(
        TspServiceGenerator.getTspServiceTslTrustAnchorCa(),
        TspServiceGenerator.getTspServiceKompCa(),
        TspServiceGenerator.getTspServiceKompCa11(),
        TspServiceGenerator.getTspServiceSmcbCa(),
        TspServiceGenerator.getTspServiceEgkCa(),
        TspServiceGenerator.getTspServiceOcspSigner());
  }

  private static List<TSPServiceType> getAlternativeTspServices() {
    return combined(
        getCommonTspServices(),
        TspServiceGenerator.getTspServiceKompCaAlt(),
        TspServiceGenerator.getTspServiceKompCaAlt33(),
        TspServiceGenerator.getTspServiceSmcbCaAlt(),
        TspServiceGenerator.getTspServiceEgkCaAlt());
  }

  private static TrustStatusListType addTrustServiceProviderWithTspServices(
      final TslContainer tslContainer, final List<TSPServiceType> tspServices) {
    final TSPType tsp = new TSPType();

    tsp.setTSPServices(new TSPServicesListType());
    tsp.setTSPInformation(getStandardTspInformation());

    tspServices.forEach(tspService -> tsp.getTSPServices().getTSPService().add(tspService));

    final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();
    tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider().add(tsp);
    tslUnsigned
        .getSchemeInformation()
        .getSchemeOperatorAddress()
        .getElectronicAddress()
        .getURI()
        .get(0)
        .setValue(PkitsConstants.GEMATIK_PKI_EMAIL_URI);

    return tslUnsigned;
  }

  static TslContainer deleteInitialTspServices(TslContainer tslContainer) {

    for (final String refSha256 :
        List.of(ARVATO_TSL_CERT_TSL_CA28_SHA256, ARVATO_TSL_OCSP_SIGNER_10_CERT_SHA256)) {

      final DeleteTspServiceForCertShaTslOperation deleteTslOp =
          new DeleteTspServiceForCertShaTslOperation(refSha256);

      tslContainer = deleteTslOp.apply(tslContainer);
    }

    return tslContainer;
  }

  private static TslContainer baseTslContainerPath(final Path tslPath) {

    TslContainer tslContainer = new TslContainer(TslReader.getTslUnsigned(tslPath));
    tslContainer = deleteInitialTspServices(tslContainer);

    final TrustStatusListType tslUnsigned = tslContainer.getAsTslUnsigned();
    TslModifier.deleteSignature(tslUnsigned);

    return new TslContainer(tslUnsigned);
  }

  private static TslContainer baseTslContainer(final boolean eccOnly) {

    if (eccOnly) {
      return baseTslContainerPath(ARVATO_TU_ECC_ONLY_TSL);
    }
    return baseTslContainerPath(ARVATO_TU_TSL);
  }

  /** TSLTypeID 1 */
  public static TrustStatusListType defaultTsl(final boolean eccOnly) {
    return addTrustServiceProviderWithTspServices(
        baseTslContainer(eccOnly), getDefaultTspServices(eccOnly));
  }

  /** TSLTypeID 2 */
  public static TrustStatusListType alternativeTsl(final boolean eccOnly) {
    return addTrustServiceProviderWithTspServices(
        baseTslContainer(eccOnly), getAlternativeTspServices());
  }

  static List<byte[]> toBytesList(final X509Certificate... certs) {
    return Arrays.stream(certs).map(GemLibPkiUtils::certToBytes).toList();
  }

  static boolean equalsAnyArray(final byte[] arr, final List<byte[]> searchArrs) {
    return searchArrs.stream().anyMatch(searchArr -> Arrays.equals(arr, searchArr));
  }

  static List<TSPServiceType> getTspServicesForCerts(
      final List<TSPServiceType> tspServices, final Path... certsPaths) {

    final X509Certificate[] certs =
        Arrays.stream(certsPaths).map(CertReader::readX509).toArray(X509Certificate[]::new);

    if (certs.length == 0) {
      throw new TslGenerationException(new IllegalArgumentException("length of certs is 0"));
    }

    final List<byte[]> bytesList = toBytesList(certs);

    return tspServices.stream()
        .filter(
            tspService -> {
              final byte[] certBytes =
                  tspService
                      .getServiceInformation()
                      .getServiceDigitalIdentity()
                      .getDigitalId()
                      .get(0)
                      .getX509Certificate();
              return equalsAnyArray(certBytes, bytesList);
            })
        .toList();
  }

  /** TSLTypeID 194 */
  public static TrustStatusListType alternativeCaRevokedLaterTsl(final boolean eccOnly) {

    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA33,
            PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
            PkitsTestDataConstants.ALTERNATIVE_EGK_CA);

    tspServicesToModify.forEach(
        tspService ->
            tspService.getServiceInformation().setServiceStatus(TslConstants.SVCSTATUS_REVOKED));

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 3 */
  // Alternative template to generate a TSL with an unspecified ServiceTypeIdentifier in TSP service
  // during tests.
  public static TrustStatusListType alternativeCaUnspecifiedStiTsl(final boolean eccOnly) {
    final List<TSPServiceType> tspServices =
        combined(
            List.of(TspServiceGenerator.getTspServiceUnspecifiedSti()),
            getAlternativeTspServices());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 202 */
  // Alternative template to generate a TSL with an additional broken CA during tests.
  public static TrustStatusListType defectAlternativeCaBrokenTsl(final boolean eccOnly) {
    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA33,
            PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
            PkitsTestDataConstants.ALTERNATIVE_EGK_CA);

    tspServicesToModify.forEach(
        tspServiceType -> {
          final byte[] certBytes =
              tspServiceType
                  .getServiceInformation()
                  .getServiceDigitalIdentity()
                  .getDigitalId()
                  .get(0)
                  .getX509Certificate();

          GemLibPkiUtils.change4Bytes(certBytes, 4);

          tspServiceType
              .getServiceInformation()
              .getServiceDigitalIdentity()
              .getDigitalId()
              .get(0)
              .setX509Certificate(certBytes);
        });

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 204 */
  // Alternative template to generate a TSL with an additional wrong (service info extension) CA
  // during tests.
  public static TrustStatusListType defectAlternativeCaWrongSrvInfoExtTsl(final boolean eccOnly) {

    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA33,
            PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
            PkitsTestDataConstants.ALTERNATIVE_EGK_CA);

    tspServicesToModify.forEach(
        tspService -> {
          final ExtensionsListType extensions = new ExtensionsListType();
          for (final CertificateType oid : List.of(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)) {
            extensions.getExtension().add(TspServiceGenerator.toExtension(oid));
          }
          tspService.getServiceInformation().setServiceInformationExtensions(extensions);
        });

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 4 */
  public static TrustStatusListType alternativeCaRevokedTsl(final boolean eccOnly) {

    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA,
            PkitsTestDataConstants.ALTERNATIVE_KOMP_CA33,
            PkitsTestDataConstants.ALTERNATIVE_SMCB_CA,
            PkitsTestDataConstants.ALTERNATIVE_EGK_CA);

    final XMLGregorianCalendar pastDate;
    pastDate = TslModifier.getXmlGregorianCalendar(GemLibPkiUtils.now().minusYears(5));

    tspServicesToModify.forEach(
        tspService -> {
          tspService.getServiceInformation().setServiceStatus(TslConstants.SVCSTATUS_REVOKED);
          tspService.getServiceInformation().setStatusStartingTime(pastDate);
        });

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** to generate TSLTypeID 172 */
  public static TrustStatusListType trustAnchorChangeFromDefaultToAlternativeFirstTsl(
      final ZonedDateTime newStatusStartingTime, final boolean eccOnly) {
    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(
                    PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR)
                .statusStartingTime(newStatusStartingTime)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 102 */
  public static TrustStatusListType trustAnchorChangeFromDefaultToAlternativeFirstTsl(
      final boolean eccOnly) {
    return trustAnchorChangeFromDefaultToAlternativeFirstTsl(GemLibPkiUtils.now(), eccOnly);
  }

  private static TrustStatusListType pkcAlternativeCaTsl(
      final X509Certificate certificate,
      final ZonedDateTime statusStartingTime,
      final boolean eccOnly) {
    final List<TSPServiceType> tspServices =
        List.of(
            TspServiceGenerator.getStandardPkcTspServiceGenerator(certificate)
                .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
                .statusStartingTime(statusStartingTime)
                .generate(),
            TspServiceGenerator.getTspServiceKompCa(),
            TspServiceGenerator.getTspServiceKompCa11(),
            TspServiceGenerator.getTspServiceSmcbCa(),
            TspServiceGenerator.getTspServiceEgkCa(),
            TspServiceGenerator.getTspServiceOcspSigner(),
            TspServiceGenerator.getTspServiceKompCaAlt(),
            TspServiceGenerator.getTspServiceKompCaAlt33(),
            TspServiceGenerator.getTspServiceSmcbCaAlt(),
            TspServiceGenerator.getTspServiceEgkCaAlt());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 174 */
  public static TrustStatusListType alternativeTrustAnchorAlternativeCaTsl(final boolean eccOnly) {
    return pkcAlternativeCaTsl(
        PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR, GemLibPkiUtils.now(), eccOnly);
  }

  /** TSLTypeID 104 */
  public static TrustStatusListType alternativeTrustAnchorTrustAnchorChangeTsl(
      final boolean eccOnly) {

    final List<TSPServiceType> tspServices =
        List.of(
            TspServiceGenerator.getStandardPkcTspServiceGenerator(
                    PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR)
                .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
                .generate(),
            TspServiceGenerator.getTspServiceKompCa(),
            TspServiceGenerator.getTspServiceKompCa11(),
            TspServiceGenerator.getTspServiceSmcbCa(),
            TspServiceGenerator.getTspServiceEgkCa(),
            TspServiceGenerator.getTspServiceOcspSigner(),
            getTspServiceGeneratorTrustAnchorChange(PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 347 */
  public static TrustStatusListType defectTrustAnchorChangeNotYetValidTsl(final boolean eccOnly) {

    final ZonedDateTime future = GemLibPkiUtils.now().plusYears(1);
    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(
                    PkitsTestDataConstants.NOT_YET_VALID_TRUST_ANCHOR)
                .statusStartingTime(future)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 345 */
  public static TrustStatusListType defectTrustAnchorChangeExpiredTsl(final boolean eccOnly) {

    final ZonedDateTime past = GemLibPkiUtils.now().minusYears(1);
    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(PkitsTestDataConstants.EXPIRED_TRUST_ANCHOR)
                .statusStartingTime(past)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 357 */
  public static TrustStatusListType defectTrustAnchorChangeTwoEntriesTsl(final boolean eccOnly) {

    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(
                    PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR)
                .generate(),
            getTspServiceGeneratorTrustAnchorChange(
                    PkitsTestDataConstants.ALTERNATIVE_SECOND_TRUST_ANCHOR)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 355 */
  // TSL_defect_TAchange_startingTimeFuture.xml
  public static TrustStatusListType defectTrustAnchorChangeStartingTimeFutureTsl(
      final boolean eccOnly) {

    final ZonedDateTime farFuture = GemLibPkiUtils.now().plusYears(15);
    return trustAnchorChangeFromDefaultToAlternativeFirstTsl(farFuture, eccOnly);
  }

  /** TSLTypeID 361 */
  // TSL_defect_TAchange_broken.xml
  public static TrustStatusListType defectTrustAnchorChangeBrokenTsl(final boolean eccOnly) {

    final byte[] brokenFirstAlternativeTrustAnchor =
        GemLibPkiUtils.certToBytes(PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR);

    final String serviceName =
        PkitsTestDataConstants.ALTERNATIVE_FIRST_TRUST_ANCHOR.getSubjectX500Principal().getName();

    GemLibPkiUtils.change4Bytes(brokenFirstAlternativeTrustAnchor, 4);

    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(null)
                .certificate(brokenFirstAlternativeTrustAnchor)
                .serviceName(serviceName)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 173 */
  // TSL_TAchange_altTA2_futureShort.xml
  public static TrustStatusListType trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(
      final ZonedDateTime newStatusStartingTime, final boolean eccOnly) {

    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(
                    PkitsTestDataConstants.ALTERNATIVE_SECOND_TRUST_ANCHOR)
                .statusStartingTime(newStatusStartingTime)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }

  /** TSLTypeID 178 */
  // TSL_invalid_altTA_expired_altCA.xml
  public static TrustStatusListType invalidAlternativeTrustAnchorExpiredAlternativeCaTsl(
      final boolean eccOnly) {

    final ZonedDateTime past = GemLibPkiUtils.now().minusYears(1);

    return pkcAlternativeCaTsl(PkitsTestDataConstants.EXPIRED_TRUST_ANCHOR, past, eccOnly);
  }

  /** TSLTypeID 180 */
  // TSL_invalid_altTA_notYetValid_altCA.xml
  public static TrustStatusListType invalidAlternativeTrustAnchorNotYetValidAlternativeCaTsl(
      final boolean eccOnly) {

    final ZonedDateTime future = GemLibPkiUtils.now().plusYears(1);
    return pkcAlternativeCaTsl(PkitsTestDataConstants.NOT_YET_VALID_TRUST_ANCHOR, future, eccOnly);
  }

  /** TSLTypeID 175 */
  // TSL_altTA2_altCA.xml
  public static TrustStatusListType alternativeTrustAnchor2AlternativeCaTsl(final boolean eccOnly) {
    return pkcAlternativeCaTsl(
        PkitsTestDataConstants.ALTERNATIVE_SECOND_TRUST_ANCHOR, GemLibPkiUtils.now(), eccOnly);
  }

  /** TSLTypeID 177 */
  // TSL_altTA2_TAchange.xml
  public static TrustStatusListType alternativeTrustAnchor2TrustAnchorChangeTsl(
      final boolean eccOnly) {
    final List<TSPServiceType> tspServices =
        List.of(
            TspServiceGenerator.getStandardPkcTspServiceGenerator(
                    PkitsTestDataConstants.ALTERNATIVE_SECOND_TRUST_ANCHOR)
                .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
                .generate(),
            TspServiceGenerator.getTspServiceKompCa(),
            TspServiceGenerator.getTspServiceKompCa11(),
            TspServiceGenerator.getTspServiceSmcbCa(),
            TspServiceGenerator.getTspServiceEgkCa(),
            TspServiceGenerator.getTspServiceOcspSigner(),
            getTspServiceGeneratorTrustAnchorChange(PkitsTestDataConstants.DEFAULT_TRUST_ANCHOR)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(eccOnly), tspServices);
  }
}
