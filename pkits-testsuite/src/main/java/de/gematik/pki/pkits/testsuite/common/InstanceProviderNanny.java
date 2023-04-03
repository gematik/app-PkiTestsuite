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

package de.gematik.pki.pkits.testsuite.common;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_HEALTH_ENDPOINT;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.Callable;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpStatus;

@Slf4j
public abstract class InstanceProviderNanny {

  private Process process;
  private boolean processIsAlreadyUp = false;

  private int port;
  private int portConfig;
  private String portJvmParam;

  private String ipAddressOrFqdn;
  private String ipAddressConfig;
  private String ipAddressJvmParam;

  private String appPath;
  private String serverId;

  protected static Optional<Integer> getProcessExitValue(final Process process) {
    try {
      return Optional.of(process.exitValue());
    } catch (final IllegalThreadStateException ex) {
      return Optional.empty();
    }
  }

  protected void setIpAddressConfig(final String ipAddressName) {
    ipAddressConfig = ipAddressName;
  }

  protected void setIpAddressJvmParam(final String ipAddressName) {
    ipAddressJvmParam = ipAddressName;
  }

  protected void setPortConfig(final int port) {
    portConfig = port;
  }

  protected void setPortJvmParam(final String portName) {
    portJvmParam = portName;
  }

  protected void setAppPath(final String path) {
    appPath = path;
  }

  protected void setServerId(final String id) {
    serverId = id;
  }

  public void startServer() {
    if (PkitsCommonUtils.isExternalStartup(appPath)) {
      setIpAddressAndPort();
      return;
    }

    if (!processIsAlreadyUp) {
      setIpAddressAndPort();
      startServerProcess();
      processIsAlreadyUp = true;
    } else {
      log.info("Instance of {} is still up", serverId);
    }
  }

  public void stopServer() {
    if (PkitsCommonUtils.isExternalStartup(appPath)) {
      return;
    }

    final Optional<Integer> processExitValue = getProcessExitValue(process);

    final String exitValue =
        processExitValue.isPresent()
            ? String.valueOf(processExitValue.get())
            : "no exit, still running ...";

    log.debug("Web server process <{}> exit value: {}", serverId, exitValue);
    log.debug("Destroy web server process <{}> now...", serverId);

    processIsAlreadyUp = false;
    process.destroy();
  }

  /** Read ipAddressOrFqdn / port from environment or config file. */
  protected void setIpAddressAndPort() {
    final String portEnv = System.getProperty(portJvmParam);
    if ((portEnv != null) && (!portEnv.isEmpty())) {
      port = Integer.parseUnsignedInt(portEnv);
    } else {
      port = portConfig;
    }

    final String ipAddressEnv = System.getProperty(ipAddressJvmParam);
    if ((ipAddressEnv != null) && (!ipAddressEnv.isEmpty())) {
      ipAddressOrFqdn = ipAddressEnv;
    } else {
      ipAddressOrFqdn = ipAddressConfig;
    }
  }

  protected void startServerProcess() {
    final ProcessBuilder processBuilder =
        new ProcessBuilder(
            "java",
            "-jar",
            appPath,
            "--server.port=" + port,
            "--server.address=" + ipAddressOrFqdn);
    processBuilder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
    processBuilder.redirectError(ProcessBuilder.Redirect.INHERIT);
    try {
      log.info("Start web server process <{}> at {}:{}", serverId, ipAddressOrFqdn, port);
      process = processBuilder.start();
      log.debug("Web server process <{}> started, PID:{}", serverId, process.pid());
    } catch (final IOException e) {
      throw new PkiCommonException("Could not start server <" + serverId + ">", e);
    }
  }

  public String waitUntilWebServerIsUp(final int timeoutSecs) {

    final String uri = "http://" + ipAddressOrFqdn + ":" + port;
    if (PkitsCommonUtils.isExternalStartup(appPath)) {
      log.info("Web server <{}> is started externally and should be up", serverId);
      return uri;
    }

    if (isProcessRunning()) {
      final Callable<Boolean> webServerIsUp = new WebServerHealthOk();
      PkitsTestSuiteUtils.waitForEvent(serverId, timeoutSecs, webServerIsUp);
      log.info("Web server <{}> should be up now", serverId);
      return uri;
    }

    processIsAlreadyUp = false;
    throw new PkiCommonException("Web server <" + serverId + "> is down");
  }

  protected boolean isProcessRunning() {
    return getProcessExitValue(process).isEmpty();
  }

  protected boolean webServerHealthOk() {
    final HttpResponse<String> response;
    try {
      final String uri = "http://" + ipAddressOrFqdn + ":" + port + WEBSERVER_HEALTH_ENDPOINT;
      log.info("Try to connect uri: {}", uri);
      response = Unirest.get(uri).asString();
      if (response.getStatus() == (HttpStatus.SC_OK)) {
        return true;
      }
    } catch (final UnirestException e) {
      // is expected when server is down
    }
    return false;
  }

  protected class WebServerHealthOk implements Callable<Boolean> {

    @Override
    public Boolean call() {
      return webServerHealthOk();
    }
  }
}
