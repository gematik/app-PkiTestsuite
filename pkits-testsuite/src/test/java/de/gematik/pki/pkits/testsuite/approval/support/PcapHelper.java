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

package de.gematik.pki.pkits.testsuite.approval.support;

import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.testsuite.approval.support.PcapManager.DeviceCommonInfo;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import pcap.spi.Service;

@Slf4j
public class PcapHelper {

  public static Service pcapService = null;
  public static List<DeviceCommonInfo> pcapDeviceCommonInfos = null;

  public static <T> Predicate<T> distinctByKey(final Function<? super T, ?> keyExtractor) {
    final Set<Object> seen = ConcurrentHashMap.newKeySet();
    return t -> seen.add(keyExtractor.apply(t));
  }

  public static void assignDevices(final TestSuiteConfig testSuiteConfig) {

    if (pcapDeviceCommonInfos != null) {
      log.info("reuse assigned devices");
      return;
    }

    log.info("assign devices to IP addresses or FQDNs: start");
    pcapService = PcapManager.createService();

    final List<DeviceCommonInfo> allDeviceCommonInfos = new ArrayList<>();

    allDeviceCommonInfos.add(
        DeviceCommonInfo.createForIpAddress(
            testSuiteConfig.getTestSuiteParameter().getCaptureInterface()));

    if (!PkitsCommonUtils.isExternalStartup(testSuiteConfig.getOcspResponder().getAppPath())) {
      allDeviceCommonInfos.add(
          DeviceCommonInfo.createForIpAddressOrFqdn(
              testSuiteConfig.getOcspResponder().getIpAddressOrFqdn()));
    }
    if (!PkitsCommonUtils.isExternalStartup(testSuiteConfig.getTslProvider().getAppPath())) {
      allDeviceCommonInfos.add(
          DeviceCommonInfo.createForIpAddressOrFqdn(
              testSuiteConfig.getTslProvider().getIpAddressOrFqdn()));
    }

    final List<String> message =
        allDeviceCommonInfos.stream()
            .map(
                deviceCommonInfo ->
                    "ipAddress: %s (ipAddressOrFqdn: %s)"
                        .formatted(deviceCommonInfo.ipAddress, deviceCommonInfo.ipAddressOrFqdn))
            .toList();

    log.info("following IP addresses are to sniff {}", message);

    final List<DeviceCommonInfo> deviceCommonInfos =
        allDeviceCommonInfos.stream()
            .filter(distinctByKey(DeviceCommonInfo::getIpAddress))
            .collect(Collectors.toList());

    log.info(
        "assign devices for the following distinct IP addresses {}",
        deviceCommonInfos.stream().map(deviceCommonInfo -> deviceCommonInfo.ipAddress).toList());

    PcapManager.assignDevicesForIpAddresses(pcapService, deviceCommonInfos);
    pcapDeviceCommonInfos = deviceCommonInfos;
    log.info("assign devices to IP addresses or FQDNs: finish");
  }
}
