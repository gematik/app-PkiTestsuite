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

package de.gematik.pki.pkits.sut.server.sim.webserverconfigs;

import static de.gematik.pki.pkits.sut.server.sim.PkiSutServerSimApplication.PRODUCT_TYPE;

import de.gematik.pki.gemlibpki.certificate.Admission;
import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.pkits.sut.server.sim.PkiSutServerSimApplication;
import de.gematik.pki.pkits.sut.server.sim.configs.HandshakeInterceptorConfig;
import de.gematik.pki.pkits.sut.server.sim.configs.OcspConfig;
import de.gematik.pki.pkits.sut.server.sim.exceptions.TosException;
import de.gematik.pki.pkits.sut.server.sim.tsl.TslProcurer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
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

  private static OcspConfig ocspConfig;

  public static void setStaticHandshakeConfig(final HandshakeInterceptorConfig handshakeConfig) {
    HandshakeInterceptor.handshakeConfig = handshakeConfig;
  }

  public static void setStaticTslProcurer(final TslProcurer tslProcurer) {
    HandshakeInterceptor.tslProcurer = tslProcurer;
  }

  public static void setStaticOcspConfig(final OcspConfig ocspConfig) {
    HandshakeInterceptor.ocspConfig = ocspConfig;
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
  public void setOcspConfig(final OcspConfig ocspConfig) {
    setStaticOcspConfig(ocspConfig);
  }

  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType)
      throws CertificateException {
    // chain: chain of certificates send by client; first cert is EndEntity
    final boolean OCSP_ENABLED = ocspConfig.isOcspEnabled();
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
                .certificateProfiles(
                    List.of(
                        CertificateProfile.CERT_PROFILE_C_HCI_AUT_RSA,
                        CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC))
                .ocspRespCache(PkiSutServerSimApplication.getOcspRespCache())
                .withOcspCheck(OCSP_ENABLED)
                .ocspTimeoutSeconds(ocspConfig.getOcspTimeoutSeconds())
                .tolerateOcspFailure(ocspConfig.isTolerateOcspFailure())
                .build();
      } catch (final TosException e) {
        throw new CertificateException("Zertifikatsprüfung nicht möglich, TSL Problem.", e);
      }

      log.info("executing TUC_PKI_018 now...");
      try {
        log.info(
            "TUC_PKI_018, Ocsp enabled: {}, certSerialNr: {}",
            OCSP_ENABLED,
            chain[0].getSerialNumber());
        final Admission admission = tucPki18Verifier.performTucPki18Checks(chain[0]);
        log.info("TUC_PKI_018 endend with success, role(s): {}", admission.getProfessionItems());
      } catch (final GemPkiException e) {
        log.info(e.getMessage());
        throw new CertificateException("TUC_PKI_018 check unsuccessful.", e);
      }
    }
  }

  @Override
  public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
    log.debug("checkServerTrusted called");
    // not used here because we are on the server side
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    log.debug("getAcceptedIssuers called");
    return new X509Certificate[] {};
  }
}
