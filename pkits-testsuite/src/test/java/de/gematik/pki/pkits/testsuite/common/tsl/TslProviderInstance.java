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

package de.gematik.pki.pkits.testsuite.common.tsl;

import de.gematik.pki.pkits.testsuite.common.InstanceProviderNanny;
import de.gematik.pki.pkits.testsuite.common.TestsuiteConstants;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestsuiteConfig;

public class TslProviderInstance extends InstanceProviderNanny {

  private static TslProviderInstance instance;

  public static InstanceProviderNanny getInstance() {
    if (instance == null) {
      instance = new TslProviderInstance();
      instance.initialize();
    }
    return instance;
  }

  private void initialize() {
    final TestsuiteConfig testsuiteConfig = TestConfigManager.getTestsuiteConfig();
    setServerId(testsuiteConfig.getTslProvider().getId());
    setAppPath(testsuiteConfig.getTslProvider().getAppPath());
    setPortJvmParam(TestsuiteConstants.TSL_PROVIDER_JVM_PARAM_PORT_NAME);
    setIpAddressJvmParam(TestsuiteConstants.TSL_PROVIDER_JVM_PARAM_IP_ADDRESS_NAME);
    setIpAddressConfig(testsuiteConfig.getTslProvider().getIpAddress());
    setPortConfig(testsuiteConfig.getTslProvider().getPort());
  }
}
