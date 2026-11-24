/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.sut.server.core.webserverconfigs;

import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_BUNDESWEHRAPOTHEKE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_DIGA;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_INSTITUTION_ARBEITSMEDIZIN;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_INSTITUTION_GEBURTSHILFE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_INSTITUTION_OEGD;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_INSTITUTION_PFLEGE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_INSTITUTION_VORSORGE_REHA;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_KOSTENTRAEGER;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_KRANKENHAUS;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_KRANKENHAUSAPOTHEKE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_MOBILE_EINRICHTUNG_RETTUNGSDIENST;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_NCPEH;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_OEFFENTLICHE_APOTHEKE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_PRAXIS_ARZT;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_PRAXIS_PSYCHOTHERAPEUT;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_SANITAETSDIENST_BUNDESWEHR;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_ZAHNARZTPRAXIS;
import static de.gematik.pki.pkits.sut.server.core.SutServerConstants.PRODUCT_TYPE;

import de.gematik.pki.gemlibpki.commons.certificate.Admission;
import de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.commons.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRespCache;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.sut.server.core.configs.HandshakeInterceptorConfig;
import de.gematik.pki.pkits.sut.server.core.configs.OcspProperties;
import de.gematik.pki.pkits.sut.server.core.exceptions.TosException;
import de.gematik.pki.pkits.sut.server.core.tsl.TslProcurer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import javax.net.ssl.X509TrustManager;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * This class is not managed by Spring, it is managed by TomcatServletCustomizer. Therefore,
 * configuration cannot be AutoWired. That's why we use HandshakeInterceptorConfig to get
 * configuration nevertheless via Spring.
 */
@Slf4j
@Component("HandshakeInterceptor")
@RequiredArgsConstructor
public final class HandshakeInterceptor implements X509TrustManager {

  @Getter private static HandshakeInterceptorConfig handshakeConfig;
  @Getter private static TslProcurer tslProcurer;
  @Getter private static OcspRespCache ocspRespCache;

  private static OcspProperties ocspProperties;

  public static void setStaticHandshakeConfig(final HandshakeInterceptorConfig handshakeConfig) {
    HandshakeInterceptor.handshakeConfig = handshakeConfig;
  }

  public static void setStaticTslProcurer(final TslProcurer tslProcurer) {
    HandshakeInterceptor.tslProcurer = tslProcurer;
  }

  public static void setStaticOcspRespCache(final OcspRespCache ocspRespCache) {
    HandshakeInterceptor.ocspRespCache = ocspRespCache;
  }

  public static void setStaticOcspProperties(final OcspProperties ocspProperties) {
    HandshakeInterceptor.ocspProperties = ocspProperties;
  }

  @Autowired
  public void setHandshakeConfig(final HandshakeInterceptorConfig handshakeConfig) {
    setStaticHandshakeConfig(handshakeConfig);
  }

  @Autowired
  public void setTslProcurer(final TslProcurer tslProcurer) {
    setStaticTslProcurer(tslProcurer);
  }

  @Autowired
  public void setOcspProperties(final OcspProperties ocspProperties) {
    setStaticOcspProperties(ocspProperties);
  }

  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType)
      throws CertificateException {
    final boolean OCSP_ENABLED = ocspProperties.isOcspEnabled();
    log.info("HandshakeInterception enabled: {}", handshakeConfig.isEnabled());
    log.info("OCSP enabled: {}", OCSP_ENABLED);

    if (handshakeConfig.isEnabled()) {
      if (log.isInfoEnabled()) {
        for (int c = 0; c < chain.length; c++) {
          final X509Certificate cert = chain[c];
          log.info(" Client certificate {}:", (c + 1));
          log.info("  Subject DN: {}", cert.getSubjectX500Principal());
          log.info("  Signature Algorithm: {}", cert.getSigAlgName());
          log.info("  Valid from: {}", cert.getNotBefore());
          log.info("  Valid until: {}", cert.getNotAfter());
          log.info("  Issuer: {}", cert.getIssuerX500Principal());
        }
      }
      log.info("read TSL");
      final TucPki018Verifier tucPki18Verifier;
      try {
        tucPki18Verifier =
            TucPki018Verifier.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tslProcurer.getTslInfoProv().getTspServices())
                .certificateProfiles(List.of(CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC))
                .ocspRespCache(ocspRespCache)
                .withOcspCheck(OCSP_ENABLED)
                .ocspTimeoutSeconds(ocspProperties.getOcspTimeoutSeconds())
                .ocspTimeToleranceProducedAtPastMilliseconds(
                    1000 * ocspProperties.getToleranceProducedAtPastSeconds())
                .ocspTimeToleranceProducedAtFutureMilliseconds(
                    1000 * ocspProperties.getToleranceProducedAtFutureSeconds())
                .tolerateOcspFailure(ocspProperties.isTolerateOcspFailure())
                .build();
      } catch (final TosException e) {
        throw new CertificateException("Zertifikatsprüfung nicht möglich, TSL Problem.", e);
      }

      log.info("executing TUC_PKI_018 now...");
      try {
        log.info(
            "TUC_PKI_018, Ocsp enabled: {}, certSerialNr: {}, hex: {}",
            OCSP_ENABLED,
            chain[0].getSerialNumber(),
            PkitsCommonUtils.toUpperHex(chain[0].getSerialNumber()));
        final Admission admission = tucPki18Verifier.performTucPki018Checks(chain[0]);

        final Set<String> allowedProfOids =
            Set.of(
                OID_PRAXIS_ARZT.getProfessionOid(),
                OID_ZAHNARZTPRAXIS.getProfessionOid(),
                OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionOid(),
                OID_KRANKENHAUS.getProfessionOid(),
                OID_OEFFENTLICHE_APOTHEKE.getProfessionOid(),
                OID_KRANKENHAUSAPOTHEKE.getProfessionOid(),
                OID_BUNDESWEHRAPOTHEKE.getProfessionOid(),
                OID_MOBILE_EINRICHTUNG_RETTUNGSDIENST.getProfessionOid(),
                OID_KOSTENTRAEGER.getProfessionOid(),
                OID_INSTITUTION_GEBURTSHILFE.getProfessionOid(),
                OID_INSTITUTION_VORSORGE_REHA.getProfessionOid(),
                OID_INSTITUTION_OEGD.getProfessionOid(),
                OID_INSTITUTION_ARBEITSMEDIZIN.getProfessionOid(),
                OID_SANITAETSDIENST_BUNDESWEHR.getProfessionOid(),
                OID_DIGA.getProfessionOid(),
                OID_NCPEH.getProfessionOid(),
                OID_INSTITUTION_PFLEGE.getProfessionOid());
        if (!TucPki018Verifier.checkAllowedProfessionOids(admission, allowedProfOids)) {
          throw new TosException(
              "Certificate not valid, profession not allowed. Expected: %s but got %s"
                  .formatted(allowedProfOids, admission.getProfessionOids()));
        }

        log.info(
            "TUC_PKI_018 endend with success, role(s): {} [{}]",
            admission.getProfessionItems(),
            admission.getProfessionOids());
      } catch (final GemPkiException e) {
        log.info(e.getMessage());
        throw new CertificateException("TUC_PKI_018 check unsuccessful.", e);
      }
    }
  }

  @Override
  public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
    log.debug("checkServerTrusted called");
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    log.debug("getAcceptedIssuers called");
    return new X509Certificate[] {};
  }
}
