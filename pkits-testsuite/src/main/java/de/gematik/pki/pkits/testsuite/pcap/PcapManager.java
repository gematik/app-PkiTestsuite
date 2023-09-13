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

package de.gematik.pki.pkits.testsuite.pcap;

import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import de.gematik.pki.pkits.testsuite.reporting.CurrentTestInfo;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.StreamSupport;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.TestInfo;
import pcap.spi.Address;
import pcap.spi.Dumper;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.Selection;
import pcap.spi.Selector;
import pcap.spi.Service;
import pcap.spi.Service.Creator;
import pcap.spi.Timeout;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.TimeoutException;
import pcap.spi.exception.error.ActivatedException;
import pcap.spi.exception.error.BreakException;
import pcap.spi.exception.error.InterfaceNotSupportTimestampTypeException;
import pcap.spi.exception.error.InterfaceNotUpException;
import pcap.spi.exception.error.NoSuchDeviceException;
import pcap.spi.exception.error.PermissionDeniedException;
import pcap.spi.exception.error.PromiscuousModePermissionDeniedException;
import pcap.spi.exception.error.RadioFrequencyModeNotSupportedException;
import pcap.spi.exception.error.TimestampPrecisionNotSupportedException;
import pcap.spi.option.DefaultLiveOptions;
import pcap.spi.util.Consumer;
import pcap.spi.util.DefaultTimeout;

@Slf4j
public class PcapManager implements Closeable {

  private final Service service;
  private final List<DeviceInfo> deviceInfos;
  private AsyncObjects asyncObjects;
  private final boolean writeIntoOneFile;

  @Getter
  public static final class DeviceCommonInfo {

    private final String ipAddressOrFqdn;
    private final String ipAddress;
    private Interface device;

    public static DeviceCommonInfo createForIpAddress(final String ipAddress) {
      return new DeviceCommonInfo(ipAddress, ipAddress);
    }

    public static DeviceCommonInfo createForIpAddressOrFqdn(final String ipAddressOrFqdn) {
      final String ipAddress = getIpAddressForIpAddressOrFqdn(ipAddressOrFqdn);
      return new DeviceCommonInfo(ipAddressOrFqdn, ipAddress);
    }

    private DeviceCommonInfo(final String ipAddressOrFqdn, final String ipAddress) {
      this.ipAddressOrFqdn = ipAddressOrFqdn;
      this.ipAddress = ipAddress;
    }
  }

  @Builder
  private static class DeviceInfo {

    private String ipAddressOrFqdn;
    private String ipAddress;
    private String pcapFilename;
    private String gzipFilename;

    private Interface device;
  }

  public static String getIpAddressForIpAddressOrFqdn(final String ipAddressOrFqdn) {
    final InetAddress address;
    try {
      address = InetAddress.getByName(ipAddressOrFqdn);
    } catch (final UnknownHostException e) {
      throw new TestSuiteException("cannot resolve ipAddressOrFqdn: " + ipAddressOrFqdn, e);
    }
    return address.getHostAddress();
  }

  @Override
  public void close() {
    if (asyncObjects != null) {
      asyncObjects.close();
    }
  }

  static class AsyncObjects implements Closeable {

    ExecutorService executor;
    Selector selector;
    Map<Pcap, Dumper> pcapDumpersMap;
    boolean writeIntoOneFile;

    @Override
    public void close() {

      if (executor != null) {
        executor.shutdown();
      }

      if (selector != null) {
        try {
          selector.close();
        } catch (final Exception e) {
          throw new TestSuiteException("problems closing pcap selector ", e);
        }
      }

      if (pcapDumpersMap != null) {
        for (final Dumper dumper : pcapDumpersMap.values()) {
          dumper.close();
          if (writeIntoOneFile) {
            break;
          }
        }

        for (final Pcap pcap : pcapDumpersMap.keySet()) {
          if (pcap != null) {
            pcap.close();
          }
        }
      }
    }
  }

  public PcapManager(
      final Service service,
      final List<DeviceCommonInfo> deviceCommonInfos,
      final String outputDirname,
      final TestInfo testInfo,
      final boolean writeIntoOneFile) {

    this.service = service;
    this.writeIntoOneFile = writeIntoOneFile;

    this.deviceInfos = new ArrayList<>();

    for (final DeviceCommonInfo deviceCommonInfo : deviceCommonInfos) {

      final String postfix = writeIntoOneFile ? "all_devices" : deviceCommonInfo.ipAddress;
      final String pcapFilename = generatePcapFilename(outputDirname, postfix, testInfo);

      final DeviceInfo deviceInfo =
          DeviceInfo.builder()
              .ipAddressOrFqdn(deviceCommonInfo.ipAddressOrFqdn)
              .ipAddress(deviceCommonInfo.ipAddress)
              .pcapFilename(pcapFilename)
              .gzipFilename(pcapFilename + ".gz")
              .device(deviceCommonInfo.device)
              .build();

      deviceInfos.add(deviceInfo);
    }
  }

  public static Service createService() {
    try {
      return Creator.create("PcapService");
    } catch (final ErrorException e) {
      throw new TestSuiteException("problem creating pcap service", e);
    }
  }

  static String generatePcapFilename(
      final String outputDirname, final String ipAddress, final TestInfo testInfo) {

    final String timestampStr = PkitsCommonUtils.asTimestampStr(GemLibPkiUtils.now());
    final String postfix = StringUtils.isNotBlank(ipAddress) ? "__" + ipAddress : "";

    final String parameterizedIndex = CurrentTestInfo.getParameterizedIndexStr(testInfo);
    return String.format(
        "%s/%s%s_%s%s.pcap",
        outputDirname,
        testInfo.getTestMethod().orElseThrow().getName(),
        parameterizedIndex,
        timestampStr,
        postfix);
  }

  private static void matchIpAddressesForDevice(
      final Interface device,
      final List<DeviceCommonInfo> deviceCommonInfos,
      final Set<String> remainingIpAddresses) {

    final List<Address> addresses =
        StreamSupport.stream(device.addresses().spliterator(), false)
            .filter(address -> address.address() != null)
            .toList();

    for (final Address address : addresses) {

      log.info(
          "CanonicalHostName: {}; HostAddress: {}; Hostname: {}; Address: {}; Address: {};"
              + " Netmask: {}; Broadcast: {}; Destination: {}",
          address.address().getCanonicalHostName(),
          address.address().getHostAddress(),
          address.address().getHostName(),
          address.address(),
          address.address(),
          address.netmask(),
          address.broadcast(),
          address.destination());

      final String currentIpAddress = address.address().getHostAddress();
      if (remainingIpAddresses.contains(currentIpAddress)) {

        deviceCommonInfos.stream()
            .filter(deviceCommonInfo -> deviceCommonInfo.ipAddress.equals(currentIpAddress))
            .forEach(deviceCommonInfo -> deviceCommonInfo.device = device);

        remainingIpAddresses.remove(currentIpAddress);
        if (remainingIpAddresses.isEmpty()) {
          break;
        }
      }
    }
  }

  /**
   * This function is used to retrieve devices associated with given IP addresses. This operation is
   * slow.
   *
   * @param service
   * @param deviceCommonInfos
   */
  public static void assignDevicesForIpAddresses(
      final Service service, final List<DeviceCommonInfo> deviceCommonInfos) {

    final List<String> allIpAddresses =
        deviceCommonInfos.stream().map(deviceCommonInfo -> deviceCommonInfo.ipAddress).toList();

    final Set<String> remainingIpAddresses = new HashSet<>(allIpAddresses);

    final Interface devices;
    try {
      devices = service.interfaces();
    } catch (final ErrorException e) {
      throw new TestSuiteException("problems retrieving network interfaces", e);
    }

    for (final Interface device : devices) {

      if (device.addresses() != null) {

        log.info(
            "device - Name: {}; Description: {}; Flags: {}",
            device.name(),
            device.description(),
            device.flags());

        matchIpAddressesForDevice(device, deviceCommonInfos, remainingIpAddresses);

        if (remainingIpAddresses.isEmpty()) {
          break;
        }
      }
    }

    if (!remainingIpAddresses.isEmpty()) {
      throw new TestSuiteException(
          "no devices for IP addresses <" + remainingIpAddresses + "> found");
    }
  }

  static Consumer<Selection> getConsumer(final Map<Pcap, Dumper> pcapDumperMap) {
    return selection -> {
      if (selection.isReadable()) {
        try {
          final Pcap pcap = (Pcap) selection.selectable();
          pcap.dispatch(
              1,
              (agr, packetHeader, packetBuffer) -> {
                final Dumper dumper = pcapDumperMap.get(pcap);
                dumper.dump(packetHeader, packetBuffer);
              },
              "");
          selection.interestOperations(Selection.OPERATION_WRITE);
        } catch (final BreakException e) {
          log.info("BreakException has occurred");
        } catch (final ErrorException | TimeoutException e) {
          throw new TestSuiteException("problems reading pcap ", e);
        }

      } else if (selection.isWritable()) {
        selection.interestOperations(Selection.OPERATION_READ);
      }
    };
  }

  static ExecutorService startCallable(
      final Selector selector, final Map<Pcap, Dumper> pcapDumperMap) {

    final ExecutorService executor = Executors.newSingleThreadExecutor();

    final Callable<Object> callableTask =
        () -> {
          final Timeout timeout = new DefaultTimeout(1_000_000L, Timeout.Precision.MICRO);

          log.info("start infinite pcap loop");
          final Consumer<Selection> consumer = getConsumer(pcapDumperMap);
          while (true) {
            try {
              selector.select(consumer, timeout);
            } catch (final TimeoutException e) {
              throw new TestSuiteException("problems processing pcap", e);
            }
          }
        };

    executor.submit(callableTask);
    return executor;
  }

  static AsyncObjects startPcap(
      final Service service, final List<DeviceInfo> deviceInfos, final boolean writeIntoOneFile) {

    try {
      final AsyncObjects asyncObjects = new AsyncObjects();
      asyncObjects.selector = service.selector();
      asyncObjects.writeIntoOneFile = writeIntoOneFile;

      asyncObjects.pcapDumpersMap = new HashMap<>();

      Dumper dumper = null;
      for (final DeviceInfo deviceInfo : deviceInfos) {

        final Pcap pcap = service.live(deviceInfo.device, new DefaultLiveOptions());
        final Selection selection =
            pcap.register(asyncObjects.selector, Selection.OPERATION_READ, null);
        assert selection.interestOperations() == Selection.OPERATION_READ;

        if (writeIntoOneFile) {
          if (dumper == null) {
            dumper = pcap.dumpOpen(deviceInfo.pcapFilename);
          }
        } else {
          dumper = pcap.dumpOpen(deviceInfo.pcapFilename);
        }
        asyncObjects.pcapDumpersMap.put(pcap, dumper);
      }

      asyncObjects.executor = startCallable(asyncObjects.selector, asyncObjects.pcapDumpersMap);

      return asyncObjects;
    } catch (final ErrorException
        | InterfaceNotSupportTimestampTypeException
        | InterfaceNotUpException
        | RadioFrequencyModeNotSupportedException
        | ActivatedException
        | PermissionDeniedException
        | NoSuchDeviceException
        | PromiscuousModePermissionDeniedException
        | TimestampPrecisionNotSupportedException e) {
      throw new TestSuiteException("problems with PCAP service", e);
    }
  }

  static void createGzipFile(final String pcapFilename, final String gzipFilename) {

    try (final OutputStream fOut = Files.newOutputStream(Paths.get(gzipFilename));
        final BufferedOutputStream buffOut = new BufferedOutputStream(fOut);
        final GzipCompressorOutputStream gzOut = new GzipCompressorOutputStream(buffOut)) {

      final Path pcapFile = Path.of(pcapFilename);
      IOUtils.copy(pcapFile.toFile(), gzOut);

    } catch (final IOException e) {
      throw new TestSuiteException("problems creating a gz file");
    }
  }

  static void stopPcap(final Collection<Pcap> pcaps) {
    for (final Pcap pcap : pcaps) {
      pcap.breakLoop();
    }
  }

  public void start() {
    this.asyncObjects = startPcap(service, deviceInfos, writeIntoOneFile);
  }

  public void stop() {
    stopPcap(asyncObjects.pcapDumpersMap.keySet());
  }

  public void createGzipFile() {
    for (final DeviceInfo deviceInfo : deviceInfos) {
      final Path path = Path.of(deviceInfo.pcapFilename);
      if (Files.exists(path)) {
        createGzipFile(deviceInfo.pcapFilename, deviceInfo.gzipFilename);
      }
    }
  }

  public void deletePcapFile() {
    for (final DeviceInfo deviceInfo : deviceInfos) {
      try {
        final Path path = Path.of(deviceInfo.pcapFilename);
        if (Files.exists(path)) {
          Files.delete(path);
        }
      } catch (final IOException e) {
        throw new TestSuiteException("problems deleting pcap file", e);
      }
    }
  }
}
