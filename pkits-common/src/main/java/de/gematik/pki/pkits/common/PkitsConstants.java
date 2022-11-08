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

package de.gematik.pki.pkits.common;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PkitsConstants {

  public static final String WEBSERVER_CONFIG_ENDPOINT = "/config";
  public static final String WEBSERVER_INFO_ENDPOINT = "/info";
  public static final String WEBSERVER_HEALTH_ENDPOINT = "/actuator/health";
  public static final String WEBSERVER_BEARER_TOKEN = "CAFEBABE";

  public static final String OCSP_SSP_ENDPOINT = "/ocsp";
  public static final String TSL_XML_ENDPOINT = "/tsl/tsl.xml";
  public static final String TSL_HASH_ENDPOINT = "/tsl/tsl.sha2";
  public static final String TSL_XML_BACKUP_ENDPOINT = "/tsl-backup/tsl.xml";
  public static final String TSL_HASH_BACKUP_ENDPOINT = "/tsl-backup/tsl.sha2";
  public static final String TSL_SEQNR_PARAM_ENDPOINT = "activeTslSeqNr";

  public static final String GEMATIK_TEST_TSP = "gematik GmbH - PKI TEST TSP";

  public static final String NOT_CONFIGURED = "not configured";

  public enum TslDownloadPoint {
    TSL_DOWNLOAD_POINT_PRIMARY,
    TSL_DOWNLOAD_POINT_BACKUP,
  }
}
