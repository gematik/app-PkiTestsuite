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

package de.gematik.pki.pkits.testsuite.ssh;

import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import de.gematik.pki.pkits.testsuite.config.SshConfig;
import de.gematik.pki.pkits.testsuite.config.TestObjectConfig;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.exceptions.DebugListener;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.scp.client.CloseableScpClient;
import org.apache.sshd.scp.client.ScpClient;
import org.apache.sshd.scp.client.ScpClientCreator;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

@Slf4j
public class SshUseCaseApplication {

  private static final boolean SEND_RECEIVE_APPLICATION_DATA = true;

  protected static final ScpTransferEventListener DEBUG_LISTENER = new DebugListener();

  private final TestObjectConfig testObjectConfig;
  private final SshConfig sshConfig;
  private final String clientKeystorePassword;
  private final Path certPath;
  private final int ocspTimeoutDelayMilliseconds;

  public SshUseCaseApplication(
      final TestSuiteConfig testSuiteConfig,
      final Path certPath,
      final int ocspTimeoutDelayMilliseconds) {

    this.testObjectConfig = testSuiteConfig.getTestObject();
    this.sshConfig = testObjectConfig.getSshConfig();
    this.clientKeystorePassword = testSuiteConfig.getClient().getKeystorePassword();

    this.certPath = certPath;
    this.ocspTimeoutDelayMilliseconds = ocspTimeoutDelayMilliseconds;
  }

  private void setIdentityProviders(final ClientSession session) {

    int c = 0;
    if (StringUtils.isNotBlank(sshConfig.getPassword())) {
      log.info("set password identity provider");
      getIdentityProviderForUsernamePassword().accept(session);
      ++c;
    }

    if (sshConfig.getPrivateKey() != null) {
      if (Files.notExists(sshConfig.getPrivateKey())) {
        throw new TestSuiteException("File " + sshConfig.getPrivateKey() + " does not exists!");
      }

      log.info("set key identity provider");
      getIdentityProviderForPrivateKey().accept(session);
      ++c;
    }

    if (c == 0) {
      log.warn("No identity provider is set!");
    }
  }

  protected ClientSession createAuthenticatedClientSession() throws IOException {
    final SshClient client = SshClient.setUpDefaultClient();
    client.start();

    ClientSession session =
        client
            .connect(sshConfig.getUsername(), sshConfig.getHost(), sshConfig.getPort())
            .verify(sshConfig.getConnectTimeoutSeconds(), TimeUnit.SECONDS)
            .getSession();
    try {
      setIdentityProviders(session);
      session.auth().verify(sshConfig.getAuthTimeoutSeconds(), TimeUnit.SECONDS);

      final ClientSession result = session;
      session = null; // avoid auto-close at finally clause
      return result;
    } finally {
      if (session != null) {
        session.close();
      }
    }
  }

  protected static ScpTransferEventListener getScpTransferEventListener(
      final ClientSession session) {
    log.debug("serverVersion: {}", session.getServerVersion());
    return log.isDebugEnabled() ? DEBUG_LISTENER : ScpTransferEventListener.EMPTY;
  }

  protected static ScpClient createScpClient(final ClientSession session) {
    final ScpClientCreator creator = ScpClientCreator.instance();
    final ScpTransferEventListener listener = getScpTransferEventListener(session);
    return creator.createScpClient(session, listener);
  }

  protected CloseableScpClient createCloseableScpClient() throws IOException {
    ClientSession session = createAuthenticatedClientSession();
    try {
      final ScpClient scpClient = createScpClient(session);
      final CloseableScpClient closer = CloseableScpClient.singleSessionInstance(scpClient);
      session = null; // avoid auto-close at finally clause
      return closer;
    } finally {
      if (session != null) {
        session.close();
      }
    }
  }

  public void uploadAllFiles(final List<Path> filesToCopy, final String remoteTargetDir)
      throws IOException {
    if (filesToCopy.isEmpty()) {
      log.warn("No files to upload!");
      return;
    }

    try (final CloseableScpClient scp = createCloseableScpClient()) {
      final Path[] filesToCopyArr = filesToCopy.toArray(Path[]::new);
      log.info(
          "start upload of local files {} to remote directory {}", filesToCopy, remoteTargetDir);
      scp.upload(
          filesToCopyArr,
          remoteTargetDir,
          ScpClient.Option.Recursive,
          ScpClient.Option.TargetIsDirectory,
          ScpClient.Option.PreserveAttributes);
      log.info(
          "finished upload of local files {} to remote directory {}", filesToCopy, remoteTargetDir);
    }
  }

  public void uploadBytesToFile(
      final byte[] content,
      final String remoteFilename,
      final Collection<PosixFilePermission> permissions)
      throws IOException {
    try (final CloseableScpClient scp = createCloseableScpClient()) {
      log.info("start upload of byte content to remote file {}", remoteFilename);

      final FileTime fileTime = FileTime.from(GemLibPkiUtils.now().toInstant());
      final ScpTimestampCommandDetails timestampDetails =
          new ScpTimestampCommandDetails(fileTime, fileTime);

      scp.upload(content, remoteFilename, permissions, timestampDetails);
      log.info("finished upload of byte content to remote file {}", remoteFilename);
    }
  }

  public void uploadSingleFileToDirectory(final String localFile, final String remoteTargetDir)
      throws IOException {
    try (final CloseableScpClient scp = createCloseableScpClient()) {
      log.info("start upload of local file {} to remote directory {}", localFile, remoteTargetDir);
      scp.upload(
          localFile,
          remoteTargetDir,
          ScpClient.Option.TargetIsDirectory,
          ScpClient.Option.PreserveAttributes);
      log.info(
          "finished upload of local file {} to remote directory {}", localFile, remoteTargetDir);
    }
  }

  public void downloadAllFiles(final String remoteFilename, final String localFilename)
      throws IOException {
    try (final CloseableScpClient scp = createCloseableScpClient()) {
      log.info("start download of remote file {} to local file {}", remoteFilename, localFilename);
      scp.download(remoteFilename, localFilename);
      log.info("finish download of remote file {} to local file {}", remoteFilename, localFilename);
    }
  }

  public Consumer<ClientSession> getIdentityProviderForUsernamePassword() {
    return session -> session.addPasswordIdentity(sshConfig.getPassword());
  }

  public Consumer<ClientSession> getIdentityProviderForPrivateKey() {
    return session -> {
      final FileKeyPairProvider provider = new FileKeyPairProvider(sshConfig.getPrivateKey());
      provider.setPasswordFinder(FilePasswordProvider.of(sshConfig.getPrivateKeyPassphrase()));
      session.setKeyIdentityProvider(provider);
    };
  }

  public int runCommand(final String command) throws IOException {

    // uses the default id_rsa and id_rsa.pub files to connect to ssh server

    try (final ClientSession session = createAuthenticatedClientSession();
        final ByteArrayOutputStream remoteOutStream = new ByteArrayOutputStream();
        final ClientChannel channel = session.createChannel(Channel.CHANNEL_EXEC, command)) {
      channel.setOut(remoteOutStream);
      channel.setErr(remoteOutStream);
      try {
        channel.open().verify(sshConfig.getChannelOpenTimeoutSeconds(), TimeUnit.SECONDS);
        try (final OutputStream pipedIn = channel.getInvertedIn()) {
          pipedIn.write(command.getBytes());
          pipedIn.flush();
        }

        final Set<ClientChannelEvent> clientChannelEvents =
            channel.waitFor(
                EnumSet.of(ClientChannelEvent.CLOSED),
                TimeUnit.SECONDS.toMillis(sshConfig.getChannelCloseTimeoutSeconds()));

        final String remoteOutStr = remoteOutStream.toString();
        log.info("remoteOutStr:\n{}", remoteOutStr);

        log.info("clientChannelEvents: {}", clientChannelEvents);

        if (channel.getExitStatus() == null) {
          throw new TestSuiteException(
              "Problems executing remote script. clientChannelEvents: " + clientChannelEvents);
        }

        final Integer returnCode = channel.getExitStatus();
        log.info("returnCode: {}", returnCode);

        return returnCode;
      } finally {
        channel.close(false);
      }
    }
  }

  String boolToStr(final boolean value) {
    return value ? "TRUE" : "FALSE";
  }

  String getOrThrow(final String value, final String fieldName) {
    if (StringUtils.isBlank(value)) {
      throw new TestSuiteException(fieldName + " is not set!");
    }
    return value;
  }

  String makeLinuxPath(final String dirname, final String filename) {
    final String separator = dirname.endsWith("/") ? "" : "/";
    return dirname + separator + filename;
  }

  String getRemoteCrtFilename(final Path p12CertPath) {
    final String crtFilename = FilenameUtils.getBaseName(p12CertPath.toString()) + ".crt";
    return makeLinuxPath(sshConfig.getRemoteTargetDir(), crtFilename);
  }

  private String getSshCommand() {

    final List<String> parts = new ArrayList<>();

    parts.add(
        "bash "
            + makeLinuxPath(
                sshConfig.getRemoteTargetDir(),
                FilenameUtils.getBaseName(testObjectConfig.getScriptPath())));
    parts.add(boolToStr(SEND_RECEIVE_APPLICATION_DATA));
    parts.add(getOrThrow(sshConfig.getAppDataHttpFwdSocket(), "sshConfig.appDataHttpFwdSocket"));
    // TODO clarify if we need getOrThrow here and below

    parts.add(FilenameUtils.getName(getRemoteCrtFilename(certPath)));
    parts.add(testObjectConfig.getIpAddressOrFqdn());
    parts.add(sshConfig.getCryptMethod());
    parts.add(String.valueOf(ocspTimeoutDelayMilliseconds));

    return String.join(" ", parts);
  }

  public int execute() {
    try {

      if (Files.notExists(sshConfig.getFilesToCopyRootDir())) {
        throw new TestSuiteException(
            "Directory "
                + sshConfig.getFilesToCopyRootDir()
                + " (in sshConfig.filesToCopyRootDir) does not exists!");
      }
      final SearchFileByWildcard searchFileByWildcard = new SearchFileByWildcard();
      final List<Path> filesToCopy =
          searchFileByWildcard.searchWithWildcard(
              sshConfig.getFilesToCopyRootDir(), sshConfig.getFilesToCopyPattern());

      final byte[] crtContent =
          CertReader.getX509FromP12(certPath, clientKeystorePassword).getEncoded();

      uploadBytesToFile(
          crtContent,
          getRemoteCrtFilename(certPath),
          EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));

      uploadAllFiles(filesToCopy, sshConfig.getRemoteTargetDir());
      final String sshCommand = getSshCommand();
      log.info("sshCommand:\n{}", sshCommand);

      final int returnCode = runCommand(sshCommand);

      final String localLogFilename =
          Path.of(ApprovalTestsBase.OUT_LOGS_DIRNAME, sshConfig.getRemoteLogFile()).toString();

      final Path targetDir = Path.of(localLogFilename).getParent();
      if ((targetDir != null) && Files.notExists(targetDir)) {
        Files.createDirectory(targetDir);
      }

      final String remoteLogFile =
          makeLinuxPath(sshConfig.getRemoteTargetDir(), sshConfig.getRemoteLogFile());
      downloadAllFiles(remoteLogFile, localLogFilename);
      return returnCode;
    } catch (final IOException | CertificateEncodingException e) {
      throw new TestSuiteException("something went wrong", e);
    }
  }
}
