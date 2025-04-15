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

package de.gematik.pki.pkits.testsuite.reporting;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URISyntaxException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class GeneratePdfTest {

  @Test
  void testHtmlGeneration() {
    assertDoesNotThrow(() -> GeneratePdf.toHtml("test"));
  }

  @Test
  void testSaveHtmlAndPdf() throws URISyntaxException {
    final Path path =
        Path.of(GeneratePdfTest.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    assertDoesNotThrow(() -> GeneratePdf.saveHtmlAndPdf("test", path.resolve("test"), true));
  }
}
