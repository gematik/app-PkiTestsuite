/*
 * Copyright 2025, gematik GmbH
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

package de.gematik.pki.pkits.testsuite.simulators;

import static de.gematik.pki.pkits.common.PkitsConstants.WEBSERVER_HEALTH_ENDPOINT;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.common.PkitsCommonUtils;
import de.gematik.pki.pkits.testsuite.common.PkitsTestSuiteUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.Callable;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestException;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.HttpStatus;

@Slf4j
public abstract class InstanceProviderNanny {

  private Process process;
  private boolean processIsAlreadyUp = false;

  private int port;
  @Setter private int portConfig;
  @Setter private String portJvmParam;

  private String ipAddressOrFqdn;
  @Setter private String ipAddressConfig;
  @Setter private String ipAddressJvmParam;

  @Setter private String appPath;
  @Setter private String serverId;

  protected static Optional<Integer> getProcessExitValue(final Process process) {
    try {
      return Optional.of(process.exitValue());
    } catch (final IllegalThreadStateException ex) {
      return Optional.empty();
    }
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
    if (process == null || PkitsCommonUtils.isExternalStartup(appPath)) {
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
    if (Files.notExists(Path.of(appPath))) {
      throw new PkiCommonException(
          "Could not find jar file to start server process <" + serverId + ">: " + appPath);
    }

    final ProcessBuilder processBuilder =
        new ProcessBuilder(
            "java", // NOSONAR java:S4036
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

    if (PkitsCommonUtils.isExternalStartup(appPath)) {
      log.info(
          "Web server <{}> is started externally and should be up, running on {}",
          serverId,
          getServerUri());
    } else if (isProcessRunning()) {
      final Callable<Boolean> webServerIsUp = new WebServerHealthOk();
      PkitsTestSuiteUtils.waitForEvent(serverId, timeoutSecs, webServerIsUp);

      log.info("Web server <{}> should be up now, running on {}", serverId, getServerUri());
    } else {
      processIsAlreadyUp = false;
      throw new PkiCommonException("Web server <" + serverId + "> is down");
    }

    return getServerUri();
  }

  protected boolean isProcessRunning() {
    return getProcessExitValue(process).isEmpty();
  }

  private String getServerUri() {
    return PkitsCommonUtils.getHttpAddressString(ipAddressOrFqdn, port);
  }

  protected boolean webServerHealthOk() {
    final HttpResponse<String> response;
    try {
      final String uri = getServerUri() + WEBSERVER_HEALTH_ENDPOINT;
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
