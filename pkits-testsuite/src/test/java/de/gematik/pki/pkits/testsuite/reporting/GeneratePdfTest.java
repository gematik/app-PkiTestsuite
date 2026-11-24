/*
 * Copyright (Change Date see Readme), gematik GmbH
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

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.List;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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

  @Test
  void testCreatePdfFromReportHtml(@TempDir final Path directory) throws IOException {
    final Path output = directory.resolve("report.pdf");
    final String html =
        GeneratePdf.htmlDocPrefix()
            + "<p>Erste&nbsp;Zeile<br>Zweite Zeile: &auml; &amp; &lt;</p>"
            + GeneratePdf.htmlDocPostfix();

    GeneratePdf.createPdf(html, output);

    try (final PDDocument pdf = Loader.loadPDF(output.toFile())) {
      assertEquals(1, pdf.getNumberOfPages());
      final var page = pdf.getPage(0).getMediaBox();
      assertEquals(420 * 72 / 25.4, page.getWidth(), 1);
      assertEquals(297 * 72 / 25.4, page.getHeight(), 1);
      final String text = new PDFTextStripper().getText(pdf).replace('\u00a0', ' ');
      assertEquals(
          List.of("Erste Zeile", "Zweite Zeile: \u00e4 & <"),
          text.lines().map(String::stripTrailing).toList());
    }
  }
}
