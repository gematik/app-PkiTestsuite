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

import com.openhtmltopdf.outputdevice.helper.BaseRendererBuilder.PageSizeUnits;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jsoup.Jsoup;
import org.jsoup.helper.W3CDom;

final class HtmlToPdfRenderer {

  private HtmlToPdfRenderer() {}

  static void render(final String html, final Path outputPdfFile) throws IOException {
    final PdfRendererBuilder renderer = new PdfRendererBuilder();
    renderer.withW3cDocument(W3CDom.convert(Jsoup.parse(html)), null);
    renderer.useDefaultPageSize(420, 297, PageSizeUnits.MM);
    try (final OutputStream output = Files.newOutputStream(outputPdfFile)) {
      renderer.toStream(output);
      renderer.run();
    }
  }
}
