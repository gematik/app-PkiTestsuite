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

package de.gematik.pki.pkits.testsuite.ssh;

import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.common.helpers.ScpAckInfo;

@Slf4j
public class DebugListener implements ScpTransferEventListener {

  @Override
  public void startFolderEvent(
      final Session s,
      final FileOperation op,
      final Path file,
      final Set<PosixFilePermission> perms) {
    logEvent("starFolderEvent", s, op, file, false, -1L, perms, null);
  }

  @Override
  public void startFileEvent(
      final Session s,
      final FileOperation op,
      final Path file,
      final long length,
      final Set<PosixFilePermission> perms) {
    logEvent("startFileEvent", s, op, file, true, length, perms, null);
  }

  @Override
  public void endFolderEvent(
      final Session s,
      final FileOperation op,
      final Path file,
      final Set<PosixFilePermission> perms,
      final Throwable thrown) {
    logEvent("endFolderEvent", s, op, file, false, -1L, perms, thrown);
  }

  @Override
  public void endFileEvent(
      final Session s,
      final FileOperation op,
      final Path file,
      final long length,
      final Set<PosixFilePermission> perms,
      final Throwable thrown) {
    logEvent("endFileEvent", s, op, file, true, length, perms, thrown);
  }

  @Override
  public void handleFileEventAckInfo(
      final Session session,
      final FileOperation op,
      final Path file,
      final long length,
      final java.util.Set<PosixFilePermission> perms,
      final ScpAckInfo ackInfo) {
    logEvent("ackInfo(" + ackInfo + ")", session, op, file, true, length, perms, null);
  }

  private void logEvent(
      final String type,
      final Session s,
      final FileOperation op,
      final Path path,
      final boolean isFile,
      final long length,
      final Collection<PosixFilePermission> perms,
      final Throwable t) {

    final StringBuilder sb = new StringBuilder(Byte.MAX_VALUE);
    sb.append(
        "    %s[%s][%s] %s=%s length=%d perms=%s"
            .formatted(type, s, op, isFile ? "File" : "Directory", path, length, perms));
    if (t != null) {
      sb.append(" ERROR=%s: %s".formatted(t.getClass().getSimpleName(), t.getMessage()));
    }
    if (log.isDebugEnabled()) {
      log.debug(sb.toString());
    }
  }
}
