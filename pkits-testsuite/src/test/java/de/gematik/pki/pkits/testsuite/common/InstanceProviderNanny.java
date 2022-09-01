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

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_HEALTH_ENDPOINT;
import static de.gematik.pki.pkits.testsuite.common.PkitsTestsuiteUtils.waitForEvent;

import de.gematik.pki.pkits.common.PkiCommonException;
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
  private boolean isUp = false;

  private int port;
  private int portConfig;
  private String portJvmParam;

  private String ipAddress;
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
    if (!isUp) {
      setIpAddressAndPort();
      startServerProcess();
      isUp = true;
    } else {
      log.info("Instance of {} is still up", serverId);
    }
  }

  public void stopServer() {
    final Optional<Integer> processExitValue = getProcessExitValue(process);
    log.debug(
        "Web server process <%s> exit value: %s"
            .formatted(
                serverId,
                processExitValue.isPresent()
                    ? String.valueOf(processExitValue.get())
                    : "no exit, still running ..."));
    log.debug("Destroy web server process <{}> now...", serverId);
    isUp = false;
    process.destroy();
  }

  /** Read ipAddress / port from environment or config file. */
  protected void setIpAddressAndPort() {
    final String portEnv = System.getProperty(portJvmParam);
    if ((portEnv != null) && (!portEnv.isEmpty())) {
      port = Integer.parseUnsignedInt(portEnv);
    } else {
      port = portConfig;
    }

    final String ipAddressEnv = System.getProperty(ipAddressJvmParam);
    if ((ipAddressEnv != null) && (!ipAddressEnv.isEmpty())) {
      ipAddress = ipAddressEnv;
    } else {
      ipAddress = ipAddressConfig;
    }
  }

  protected void startServerProcess() {
    final ProcessBuilder processBuilder =
        new ProcessBuilder(
            "java", "-jar", appPath, "--server.port=" + port, "--server.address=" + ipAddress);
    processBuilder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
    processBuilder.redirectError(ProcessBuilder.Redirect.INHERIT);
    try {
      log.info("Start web server process <{}> at {}:{}", serverId, ipAddress, port);
      process = processBuilder.start();
      log.debug("Web server process <{}> started, PID:{}", serverId, process.pid());
    } catch (final IOException e) {
      throw new PkiCommonException("Could not start server <" + serverId + ">", e);
    }
  }

  public String waitUntilWebServerIsUp(final int timeoutSecs) {
    if (isProcessRunning()) {
      final Callable<Boolean> webServerIsUp = new WebServerHealthOk();
      waitForEvent("webServerIsUp", timeoutSecs, webServerIsUp);
      log.info("Web server <{}> should be up now", serverId);
      return "http://" + ipAddress + ":" + port;
    } else {
      isUp = false;
      throw new PkiCommonException("Web server <" + serverId + "> is down");
    }
  }

  protected boolean isProcessRunning() {
    return getProcessExitValue(process).isEmpty();
  }

  protected boolean webServerHealthOk() {
    final HttpResponse<String> response;
    try {
      final String uri = "http://" + ipAddress + ":" + port + WEBSERVER_HEALTH_ENDPOINT;
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
