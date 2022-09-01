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

package de.gematik.pki.pkits.testsuite.common;

import java.nio.file.Path;

public class TestsuiteConstants {

  public static final String TSL_PROVIDER_JVM_PARAM_IP_ADDRESS_NAME = "TSL_PROVIDER_IP";
  public static final String TSL_PROVIDER_JVM_PARAM_PORT_NAME = "TSL_PROVIDER_PORT";

  public static final String OCSP_RESPONDER_JVM_PARAM_IP_ADDRESS_NAME = "OCSP_RESPONDER_IP";
  public static final String OCSP_RESPONDER_JVM_PARAM_PORT_NAME = "OCSP_RESPONDER_PORT";

  public static final Path PKITS_CFG_DIR = Path.of("../config");
  public static final Path PKITS_CFG_FILE_PATH = PKITS_CFG_DIR.resolve("pkits.yml");

  public static final Path TSL_SEQNR_FILE_PATH = PKITS_CFG_DIR.resolve("tslSeqNr.cfg");

  public static final String OCSP_SIGNER_FILENAME = "ee_default.p12";
  public static final String OCSP_SIGNER_NOT_IN_TSL_FILENAME = "ee_not-in-tsl.p12";
  public static final String OCSP_SIGNER_DIFFERENT_KEY = "ee_different-key.p12";

  public enum PKITS_CERT {
    PKITS_CERT_VALID,
    PKITS_CERT_INVALID
  }
}
