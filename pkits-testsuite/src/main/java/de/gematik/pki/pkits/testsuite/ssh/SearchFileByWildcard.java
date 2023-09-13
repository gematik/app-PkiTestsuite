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

package de.gematik.pki.pkits.testsuite.ssh;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

class SearchFileByWildcard {

  List<Path> searchWithWildcard(final Path rootDir, final String pattern) throws IOException {
    final List<Path> matchesList = new ArrayList<>();
    final FileVisitor<Path> matcherVisitor =
        new SimpleFileVisitor<>() {
          @Override
          public FileVisitResult visitFile(final Path file, final BasicFileAttributes attribs) {
            final FileSystem fileSystem = FileSystems.getDefault();
            final PathMatcher pathMatcher = fileSystem.getPathMatcher(pattern);
            final Path filename = file.getFileName();
            if (pathMatcher.matches(filename)) {
              matchesList.add(file);
            }
            return FileVisitResult.CONTINUE;
          }
        };
    Files.walkFileTree(rootDir, matcherVisitor);
    return matchesList;
  }
}
