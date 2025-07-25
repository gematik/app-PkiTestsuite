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

package de.gematik.pki.pkits.tls.client;

import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class BlindTrustManager implements X509TrustManager {

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[] {};
  }

  @SuppressWarnings("java:S4830")
  @Override
  public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
    // we trust all
  }

  @SuppressWarnings("java:S4830")
  @Override
  public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
    // we trust all
  }
}
