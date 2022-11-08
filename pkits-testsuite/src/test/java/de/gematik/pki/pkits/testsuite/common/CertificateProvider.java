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

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants.PKITS_CERT;
import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.AnnotationConsumer;

public class CertificateProvider implements ArgumentsProvider, AnnotationConsumer<VariableSource> {

  private static String certDir;

  public static Stream<Path> getFilesFromDir(final String directory) {
    final List<Path> fileList = new ArrayList<>();
    try {
      Files.walkFileTree(
          Path.of(directory).normalize(),
          new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(final Path file, final BasicFileAttributes attrs) {

              if (!Files.isDirectory(file)) {
                fileList.add(file.toAbsolutePath());
              }
              return FileVisitResult.CONTINUE;
            }
          });
    } catch (final IOException e) {
      throw new UncheckedIOException("Fehler beim Lesen des Verzeichnisses: " + directory, e);
    }
    return fileList.stream();
  }

  @Override
  public Stream<? extends Arguments> provideArguments(final ExtensionContext extensionContext) {
    return getFilesFromDir(Path.of(certDir).toString()).map(Arguments::of);
  }

  @Override
  public void accept(final VariableSource variableSource) {
    final PKITS_CERT pkits_cert = variableSource.value();
    final TestSuiteConfig testSuiteConfig = TestConfigManager.getTestSuiteConfig();
    switch (pkits_cert) {
      case PKITS_CERT_VALID -> certDir = testSuiteConfig.getClient().getKeystorePathValidCerts();
      case PKITS_CERT_INVALID -> certDir =
          testSuiteConfig.getClient().getKeystorePathInvalidCerts();
      default -> throw new PkiCommonException("Unknown PKITS_CERT");
    }
    certDir = PkitsTestSuiteUtils.buildAbsolutePath(certDir).toString();
  }
}
