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

package de.gematik.pki.pkits.testsuite.common;

import de.gematik.pki.pkits.testsuite.config.TestConfigManager;
import de.gematik.pki.pkits.testsuite.config.TestObjectType;
import de.gematik.pki.pkits.testsuite.exceptions.TestSuiteException;
import java.io.IOException;
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

  private Path eeCertsDir;
  private Path issuerCert;

  public static Stream<Path> getFilesFromDir(final Path directory) {
    final List<Path> fileList = new ArrayList<>();
    try {
      Files.walkFileTree(
          directory.normalize(),
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
      throw new TestSuiteException("Fehler beim Lesen des Verzeichnisses: " + directory, e);
    }
    return fileList.stream();
  }

  @Override
  public Stream<? extends Arguments> provideArguments(final ExtensionContext extensionContext) {
    final Stream<Path> eeCertFiles = getFilesFromDir(eeCertsDir);
    return eeCertFiles.map(eeCertFile -> Arguments.arguments(eeCertFile, issuerCert));
  }

  @Override
  public void accept(final VariableSource variableSource) {
    final PkitsCertType pkitsCertType = variableSource.value();
    final TestObjectType testObjectType =
        TestConfigManager.getTestSuiteConfig().getTestObject().getTestObjectType();

    switch (pkitsCertType) {
      case PKITS_CERT_VALID -> {
        eeCertsDir = testObjectType.getClientKeystorePathValidCerts();
        issuerCert = testObjectType.getClientDefaultIssuerCertPath();
      }
      case PKITS_CERT_VALID_ALTERNATIVE -> {
        eeCertsDir = testObjectType.getClientKeystorePathAlternativeCerts();
        issuerCert = testObjectType.getClientAlternativeIssuerCertPath();
      }
      case PKITS_CERT_INVALID -> {
        eeCertsDir = testObjectType.getClientKeystorePathInvalidCerts();
        issuerCert = testObjectType.getClientDefaultIssuerCertPath();
      }
      default -> { // PkitsCertType.PKITS_CERT_VALID_RSA
        eeCertsDir = testObjectType.getClientKeystorePathRsaCerts();
        issuerCert = testObjectType.getClientDefaultIssuerRsaCertPath();
      }
    }
    eeCertsDir = PkitsTestSuiteUtils.buildAbsolutePathForDir(eeCertsDir);
    issuerCert = PkitsTestSuiteUtils.buildAbsolutePath(issuerCert);
  }
}
