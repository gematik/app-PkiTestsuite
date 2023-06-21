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

package de.gematik.pki.pkits.testsuite.common;

import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.params.provider.Arguments;

@Slf4j
public class TestSuiteConstants {

  public static final String TSL_PROVIDER_JVM_PARAM_IP_ADDRESS_NAME = "TSL_PROVIDER_IP";
  public static final String TSL_PROVIDER_JVM_PARAM_PORT_NAME = "TSL_PROVIDER_PORT";

  public static final String OCSP_RESPONDER_JVM_PARAM_IP_ADDRESS_NAME = "OCSP_RESPONDER_IP";
  public static final String OCSP_RESPONDER_JVM_PARAM_PORT_NAME = "OCSP_RESPONDER_PORT";

  public static final Path PKITS_CFG_DIR = Path.of("./config");

  public static final Path TSL_SEQNR_FILE_PATH = PKITS_CFG_DIR.resolve("tslSeqNr.cfg");
  public static final Path PKITS_CFG_FILE_PATH;

  public static final Path VALID_ISSUER_CERT_TSL_CA8_PATH =
      Path.of("./testDataTemplates/certificates/ecc/trustAnchor/GEM.TSL-CA8_TEST-ONLY.pem");

  public static final String OCSP_SIGNER_FILENAME = "OCSP_Signer_09_ecc_TEST-ONLY.p12";
  public static final String OCSP_SIGNER_NOT_IN_TSL_FILENAME = "ee_not-in-tsl.p12";
  public static final String OCSP_SIGNER_DIFFERENT_KEY = "ee_different-key.p12";

  static {
    final String pkitsConfigPath = System.getProperty("pkitsConfig");

    if (!StringUtils.isBlank(pkitsConfigPath)) {
      PKITS_CFG_FILE_PATH = Path.of(pkitsConfigPath);
    } else {
      PKITS_CFG_FILE_PATH = PKITS_CFG_DIR.resolve("pkits.yml");
    }

    log.info("pkits yml config file is set to {}", PKITS_CFG_FILE_PATH);
  }

  public enum PkitsCertType {
    PKITS_CERT_VALID,
    PKITS_CERT_INVALID
  }

  public enum DtoDateConfigOption {
    THIS_UPDATE,
    PRODUCED_AT,
    NEXT_UPDATE
  }

  public static Stream<Arguments> provideOcspResponseVariousStatusAndResponseBytes() {
    final List<Arguments> argumentsList = new ArrayList<>();
    for (final OCSPRespStatus ocspRespStatus :
        List.of(
            OCSPRespStatus.INTERNAL_ERROR,
            OCSPRespStatus.MALFORMED_REQUEST,
            OCSPRespStatus.SIG_REQUIRED,
            OCSPRespStatus.TRY_LATER,
            OCSPRespStatus.UNAUTHORIZED)) {
      for (final boolean withResponseBytes : List.of(true, false)) {
        argumentsList.add(Arguments.of(ocspRespStatus, withResponseBytes));
      }
    }
    return argumentsList.stream();
  }
}
