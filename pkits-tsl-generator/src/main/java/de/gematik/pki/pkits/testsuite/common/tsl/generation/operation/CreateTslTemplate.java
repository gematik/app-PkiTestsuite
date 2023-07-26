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

import static de.gematik.pki.pkits.testsuite.common.tsl.generation.operation.TspServiceGenerator.getTspServiceGeneratorTrustAnchorChange;

import de.gematik.pki.gemlibpki.certificate.CertificateType;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TslModifier;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsConstants;
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
import java.time.temporal.ChronoUnit;
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

  static final Path ARVATO_TU_TSL = Path.of("./testDataTemplates/tsl/ECC-RSA_TSL-test.xml");

  static final String AVARTO_TSL_CERT_TSL_CA28_SHA256 =
      "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a";
  public static final String AVARTO_TSL_OCSP_SIGNER_10_CERT_SHA256 =
      "570026f5fa80b05454bbf6eb5480a02140a58911cb128392c773240d36186062";
  public static final String AVARTO_TSL_OCSP_SIGNER_8_CERT_SHA256 =
      "e7c0631465b921ebe90dbec2cbc4da2f9380a0d3809d87172882e8b376255539";

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

  private static List<TSPServiceType> getDefaultTspServices() {
    return combined(
        List.of(
            TspServiceGenerator.getTspServiceKompCaRsa(),
            TspServiceGenerator.getTspServiceSmcbCaRsa(),
            TspServiceGenerator.getTspServiceOcspSignerRsa()),
        getCommonTspServices());
  }

  private static List<TSPServiceType> getCommonTspServices() {
    return List.of(
        TspServiceGenerator.getTspServiceTslTrustAnchorCa(),
        TspServiceGenerator.getTspServiceKompCa(),
        TspServiceGenerator.getTspServiceSmcbCa(),
        TspServiceGenerator.getTspServiceOcspSigner());
  }

  private static List<TSPServiceType> getAlternativeTspServices() {
    return combined(
        getCommonTspServices(),
        TspServiceGenerator.getTspServiceKompCaAlt(),
        TspServiceGenerator.getTspServiceSmcbCaAlt());
  }

  private static TrustStatusListType addTrustServiceProviderWithTspServices(
      final TslContainer tslContainer, final List<TSPServiceType> tspServices) {
    final TSPType tsp = new TSPType();

    tsp.setTSPServices(new TSPServicesListType());
    tsp.setTSPInformation(getStandardTspInformation());

    tspServices.forEach(tspService -> tsp.getTSPServices().getTSPService().add(tspService));

    final TrustStatusListType tsl = tslContainer.getAsTsl();
    tsl.getTrustServiceProviderList().getTrustServiceProvider().add(tsp);
    tsl.getSchemeInformation()
        .getSchemeOperatorAddress()
        .getElectronicAddress()
        .getURI()
        .get(0)
        .setValue(PkitsConstants.GEMATIK_PKI_EMAIL_URI);

    return tsl;
  }

  static TslContainer deleteInitialTspServices(TslContainer tslContainer) {

    for (final String refSha256 :
        List.of(
            AVARTO_TSL_CERT_TSL_CA28_SHA256,
            AVARTO_TSL_OCSP_SIGNER_10_CERT_SHA256,
            AVARTO_TSL_OCSP_SIGNER_8_CERT_SHA256)) {

      final DeleteTspServiceForCertShaTslOperation deleteTslOp =
          new DeleteTspServiceForCertShaTslOperation(refSha256);

      tslContainer = deleteTslOp.apply(tslContainer);
    }

    return tslContainer;
  }

  private static TslContainer baseTslContainer() {

    TslContainer tslContainer = new TslContainer(TslReader.getTsl(ARVATO_TU_TSL));
    tslContainer = deleteInitialTspServices(tslContainer);

    final TrustStatusListType tsl = tslContainer.getAsTsl();
    TslModifier.deleteSignature(tsl);

    return new TslContainer(tsl);
  }

  /** TSLTypeID 1 */
  public static TrustStatusListType defaultTsl() {
    return addTrustServiceProviderWithTspServices(baseTslContainer(), getDefaultTspServices());
  }

  /** TSLTypeID 2 */
  public static TrustStatusListType alternativeTsl() {
    return addTrustServiceProviderWithTspServices(baseTslContainer(), getAlternativeTspServices());
  }

  static List<byte[]> toBytesList(final X509Certificate... certs) {
    return Arrays.stream(certs).map(GemLibPkiUtils::certToBytes).toList();
  }

  static boolean equalsAnyArray(final byte[] arr, final List<byte[]> searchArrs) {
    return searchArrs.stream().anyMatch(searchArr -> Arrays.equals(arr, searchArr));
  }

  static List<TSPServiceType> getTspServicesForCerts(
      final List<TSPServiceType> tspServices, final X509Certificate... certs) {

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
  public static TrustStatusListType alternativeCaRevokedLaterTsl() {

    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            TspServiceGenerator.CERT_KOMP_CA_ALTERNATIVE,
            TspServiceGenerator.CERT_SMCB_CA_ALTERNATIVE);

    tspServicesToModify.forEach(
        tspService ->
            tspService.getServiceInformation().setServiceStatus(TslConstants.SVCSTATUS_REVOKED));

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 3 */
  // Alternative template to generate a TSL with an unspecified ServiceTypeIdentifier in TSP service
  // during tests.
  public static TrustStatusListType alternativeCaUnspecifiedStiTsl() {
    final List<TSPServiceType> tspServices =
        combined(
            List.of(TspServiceGenerator.getTspServiceUnspecifiedSti()),
            getAlternativeTspServices());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 202 */
  // Alternative template to generate a TSL with an additional broken CA during tests.
  public static TrustStatusListType defectAlternativeCaBrokenTsl() {
    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            TspServiceGenerator.CERT_KOMP_CA_ALTERNATIVE,
            TspServiceGenerator.CERT_SMCB_CA_ALTERNATIVE);

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

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 204 */
  // Alternative template to generate a TSL with an additional wrong (service info extension) CA
  // during tests.
  public static TrustStatusListType defectAlternativeCaWrongSrvInfoExtTsl() {

    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            TspServiceGenerator.CERT_KOMP_CA_ALTERNATIVE,
            TspServiceGenerator.CERT_SMCB_CA_ALTERNATIVE);

    tspServicesToModify.forEach(
        tspService -> {
          final ExtensionsListType extensions = new ExtensionsListType();
          for (final CertificateType oid :
              List.of(
                  CertificateType.CERT_TYPE_EGK_ENC,
                  CertificateType.CERT_TYPE_EGK_ENCV,
                  CertificateType.CERT_TYPE_EGK_AUT,
                  CertificateType.CERT_TYPE_EGK_AUTN)) {
            extensions.getExtension().add(TspServiceGenerator.toExtension(oid));
          }
          tspService.getServiceInformation().setServiceInformationExtensions(extensions);
        });

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 4 */
  public static TrustStatusListType alternativeCaRevokedTsl() {

    final List<TSPServiceType> tspServices = getAlternativeTspServices();

    final List<TSPServiceType> tspServicesToModify =
        getTspServicesForCerts(
            tspServices,
            TspServiceGenerator.CERT_KOMP_CA_ALTERNATIVE,
            TspServiceGenerator.CERT_SMCB_CA_ALTERNATIVE);

    final XMLGregorianCalendar pastDate;
    pastDate = TslModifier.getXmlGregorianCalendar(GemLibPkiUtils.now().minus(5, ChronoUnit.YEARS));

    tspServicesToModify.forEach(
        tspService -> {
          tspService.getServiceInformation().setServiceStatus(TslConstants.SVCSTATUS_REVOKED);
          tspService.getServiceInformation().setStatusStartingTime(pastDate);
        });

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** to generate TSLTypeID 172 */
  public static TrustStatusListType trustAnchorChangeFromDefaultToAlternativeFirstTsl(
      final ZonedDateTime newStatusStartingTime) {
    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_FIRST_ALTERNATIVE)
                .statusStartingTime(newStatusStartingTime)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 102 */
  public static TrustStatusListType trustAnchorChangeFromDefaultToAlternativeFirstTsl() {
    return trustAnchorChangeFromDefaultToAlternativeFirstTsl(GemLibPkiUtils.now());
  }

  private static TrustStatusListType pkcAlternativeCaTsl(
      final X509Certificate certificate, final ZonedDateTime statusStartingTime) {
    final List<TSPServiceType> tspServices =
        List.of(
            TspServiceGenerator.getStandardPkcTspServiceGenerator(certificate)
                .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
                .statusStartingTime(statusStartingTime)
                .generate(),
            TspServiceGenerator.getTspServiceKompCa(),
            TspServiceGenerator.getTspServiceSmcbCa(),
            TspServiceGenerator.getTspServiceOcspSigner(),
            TspServiceGenerator.getTspServiceKompCaAlt(),
            TspServiceGenerator.getTspServiceSmcbCaAlt());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 174 */
  public static TrustStatusListType alternativeTrustAnchorAlternativeCaTsl() {
    return pkcAlternativeCaTsl(TspServiceGenerator.CERT_TA_FIRST_ALTERNATIVE, GemLibPkiUtils.now());
  }

  /** TSLTypeID 104 */
  public static TrustStatusListType alternativeTrustAnchorTrustAnchorChangeTsl() {

    final List<TSPServiceType> tspServices =
        List.of(
            TspServiceGenerator.getStandardPkcTspServiceGenerator(
                    TspServiceGenerator.CERT_TA_FIRST_ALTERNATIVE)
                .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
                .generate(),
            TspServiceGenerator.getTspServiceKompCa(),
            TspServiceGenerator.getTspServiceSmcbCa(),
            TspServiceGenerator.getTspServiceOcspSigner(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_DEFAULT)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 347 */
  public static TrustStatusListType defectTrustAnchorChangeNotYetValidTsl() {

    final ZonedDateTime future = GemLibPkiUtils.now().plus(1, ChronoUnit.YEARS);
    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_NOT_YET_VALID)
                .statusStartingTime(future)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 345 */
  public static TrustStatusListType defectTrustAnchorChangeExpiredTsl() {

    final ZonedDateTime past = GemLibPkiUtils.now().minus(1, ChronoUnit.YEARS);
    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_EXPIRED)
                .statusStartingTime(past)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 357 */
  public static TrustStatusListType defectTrustAnchorChangeTwoEntriesTsl() {

    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_FIRST_ALTERNATIVE)
                .generate(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_SECOND_ALTERNATIVE)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 355 */
  // TSL_defect_TAchange_startingTimeFuture.xml

  public static TrustStatusListType defectTrustAnchorChangeStartingTimeFutureTsl() {

    final ZonedDateTime farFuture = GemLibPkiUtils.now().plus(15, ChronoUnit.YEARS);
    return trustAnchorChangeFromDefaultToAlternativeFirstTsl(farFuture);
  }

  /** TSLTypeID 361 */
  // TSL_defect_TAchange_broken.xml

  public static TrustStatusListType defectTrustAnchorChangeBrokenTsl() {

    final byte[] brokenFirstAlternativeTrustAnchor =
        GemLibPkiUtils.certToBytes(TspServiceGenerator.CERT_TA_FIRST_ALTERNATIVE);

    final String serviceName =
        TspServiceGenerator.CERT_TA_FIRST_ALTERNATIVE.getSubjectX500Principal().getName();

    GemLibPkiUtils.change4Bytes(brokenFirstAlternativeTrustAnchor, 4);

    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(null)
                .certificate(brokenFirstAlternativeTrustAnchor)
                .serviceName(serviceName)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 173 */
  // TSL_TAchange_altTA2_futureShort.xml
  public static TrustStatusListType trustAnchorChangeAlternativeTrustAnchor2FutureShortTsl(
      final ZonedDateTime newStatusStartingTime) {

    final List<TSPServiceType> tspServices =
        combined(
            getCommonTspServices(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_SECOND_ALTERNATIVE)
                .statusStartingTime(newStatusStartingTime)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }

  /** TSLTypeID 178 */
  // TSL_invalid_altTA_expired_altCA.xml
  public static TrustStatusListType invalidAlternativeTrustAnchorExpiredAlternativeCaTsl() {

    final ZonedDateTime past = GemLibPkiUtils.now().minus(1, ChronoUnit.YEARS);

    return pkcAlternativeCaTsl(TspServiceGenerator.CERT_TA_EXPIRED, past);
  }

  /** TSLTypeID 180 */
  // TSL_invalid_altTA_notYetValid_altCA.xml

  public static TrustStatusListType invalidAlternativeTrustAnchorNotYetValidAlternativeCaTsl() {

    final ZonedDateTime future = GemLibPkiUtils.now().plus(1, ChronoUnit.YEARS);
    return pkcAlternativeCaTsl(TspServiceGenerator.CERT_TA_NOT_YET_VALID, future);
  }

  /** TSLTypeID 175 */
  // TSL_altTA2_altCA.xml
  public static TrustStatusListType alternativeTrustAnchor2AlternativeCaTsl() {
    return pkcAlternativeCaTsl(
        TspServiceGenerator.CERT_TA_SECOND_ALTERNATIVE, GemLibPkiUtils.now());
  }

  /** TSLTypeID 177 */
  // TSL_altTA2_TAchange.xml
  public static TrustStatusListType alternativeTrustAnchor2TrustAnchorChangeTsl() {
    final List<TSPServiceType> tspServices =
        List.of(
            TspServiceGenerator.getStandardPkcTspServiceGenerator(
                    TspServiceGenerator.CERT_TA_SECOND_ALTERNATIVE)
                .addServiceInformationExtension(CertificateType.TSL_FIELD_TSL_PLACEHOLDER)
                .generate(),
            TspServiceGenerator.getTspServiceKompCa(),
            TspServiceGenerator.getTspServiceSmcbCa(),
            TspServiceGenerator.getTspServiceOcspSigner(),
            getTspServiceGeneratorTrustAnchorChange(TspServiceGenerator.CERT_TA_DEFAULT)
                .generate());

    return addTrustServiceProviderWithTspServices(baseTslContainer(), tspServices);
  }
}
