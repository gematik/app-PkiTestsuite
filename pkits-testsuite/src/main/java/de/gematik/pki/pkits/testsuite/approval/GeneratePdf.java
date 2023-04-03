/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.approval;

import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.common.TestSuiteConstants;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

@Slf4j
public class GeneratePdf {

  private static String toHtml(String text) {
    text = StringEscapeUtils.escapeHtml4(text);
    text = StringUtils.replace(text, "\n", "<br>\n");
    text = StringUtils.replace(text, "\r", "");
    text = StringUtils.replace(text, "\t", "    ");
    text = StringUtils.replace(text, "  ", " &nbsp;");
    text = StringUtils.replace(text, "\n ", "\n&nbsp;");
    return text;
  }

  private static final String HTML_PREFIX =
      """
      <!DOCTYPE html>
      <html>
        <head>
          <style>
      p {
        display:block;
        margin-left:40px;
        text-indent: -1em;
      }
          </style>
        </head>
      <body>
      """;

  private static final String HTML_POSTFIX = "</body></html>";

  public static void savePdf(final String logFilename, final boolean alsoWithTimestamp)
      throws IOException {

    final Path reportsDir = Path.of("./out/testreport/");
    final Path logFile = Path.of(logFilename);
    final String baseFilename = reportsDir + FilenameUtils.getBaseName(logFilename);

    if (!Files.exists(reportsDir)) {
      Files.createDirectory(reportsDir);
    }

    final Path outputHtmlFile = Path.of(baseFilename + ".html");
    final Path outputPdfFile = Path.of(baseFilename + ".pdf");

    log.info("read content of pkits yml config file: {}", TestSuiteConstants.PKITS_CFG_FILE_PATH);
    final String configContent =
        Files.readString(TestSuiteConstants.PKITS_CFG_FILE_PATH, StandardCharsets.UTF_8);

    log.info("read content of the log file: {}", logFile);
    final String logContent = Files.readString(logFile, StandardCharsets.UTF_8);

    final String allContent = String.join("\n\n", configContent, logContent);
    final String htmlContent = String.join("\n\n", HTML_PREFIX, toHtml(allContent), HTML_POSTFIX);

    if (alsoWithTimestamp) {
      final String timestamp =
          "_" + GemLibPkiUtils.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
      final Path outputHtmlFileWithTimestamp = Path.of(baseFilename + "_" + timestamp + ".html");
      final Path outputPdfFileWithTimestamp = Path.of(baseFilename + "_" + timestamp + ".pdf");

      log.info(
          "save pdf and html files: {}, {}",
          outputPdfFileWithTimestamp,
          outputHtmlFileWithTimestamp);
      createPdf(htmlContent, outputPdfFileWithTimestamp);
      Files.writeString(outputHtmlFileWithTimestamp, htmlContent, StandardCharsets.UTF_8);
    }

    log.info("save pdf and html files: {}, {}", outputPdfFile, outputHtmlFile);
    createPdf(htmlContent, outputPdfFile);
    Files.writeString(outputHtmlFile, htmlContent, StandardCharsets.UTF_8);
    log.info("done!");
  }

  public static void createPdf(final String html, final Path outputPdfFile) throws IOException {
    log.info("create pdf file: {}", outputPdfFile);
    final PdfDocument pdfDocument = new PdfDocument(new PdfWriter(outputPdfFile.toFile()));

    pdfDocument.setDefaultPageSize(PageSize.A3.rotate());
    HtmlConverter.convertToPdf(html, pdfDocument, null);
  }

  public static void main(final String[] args) throws IOException {

    final String logFilename =
        StringUtils.defaultString(ArrayUtils.get(args, 0), "./out/logs/pkits-testsuite-test.log");

    savePdf(logFilename, true);
  }
}
