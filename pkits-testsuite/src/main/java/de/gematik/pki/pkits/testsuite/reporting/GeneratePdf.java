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

package de.gematik.pki.pkits.testsuite.reporting;

import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.pkits.testsuite.approval.ApprovalTestsBase;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

@Slf4j
public class GeneratePdf {

  @Getter @Setter private static boolean noHtml = false;

  public static String htmlDocPrefix() {
    return noHtml
        ? ""
        : """
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
  }

  public static String htmlDocPostfix() {
    return noHtml ? "" : "</body></html>";
  }

  public static String toHtml(String text) {
    if (!noHtml) {
      text = StringEscapeUtils.escapeHtml4(text);
      text = StringUtils.replace(text, "\n", "<br>\n");
      text = StringUtils.replace(text, "\r", "");
      text = StringUtils.replace(text, "\t", "    ");
      text = StringUtils.replace(text, "  ", " &nbsp;");
      text = StringUtils.replace(text, "\n ", "\n&nbsp;");
    }
    return text;
  }

  public static String htmlHeader(final int headerLevel, final String content) {
    return noHtml ? content : "<h%s>%s</h%s>".formatted(headerLevel, content, headerLevel);
  }

  public static String htmlBr() {
    return noHtml ? "" : "<br>";
  }

  public static String htmlPre(final String content) {
    return noHtml ? content : "<pre>%s</pre>".formatted(content);
  }

  public static String htmlTt(final String content) {
    return noHtml ? content : "<tt>%s</tt>".formatted(content);
  }

  public static void saveHtmlAndPdf(
      final String reportContent, final Path baseFilename, final boolean onlyWithTimestamp)
      throws IOException {

    final Path outputHtmlFile = Path.of(baseFilename + ".html");
    final Path outputPdfFile = Path.of(baseFilename + ".pdf");

    final String timestamp =
        "_" + GemLibPkiUtils.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
    final Path outputHtmlFileWithTimestamp = Path.of(baseFilename + "_" + timestamp + ".html");
    final Path outputPdfFileWithTimestamp = Path.of(baseFilename + "_" + timestamp + ".pdf");

    log.info(
        "save pdf and html files: {}, {}", outputPdfFileWithTimestamp, outputHtmlFileWithTimestamp);
    createPdf(reportContent, outputPdfFileWithTimestamp);
    Files.writeString(outputHtmlFileWithTimestamp, reportContent, StandardCharsets.UTF_8);

    if (!onlyWithTimestamp) {
      log.info("save pdf and html files: {}, {}", outputPdfFile, outputHtmlFile);
      createPdf(reportContent, outputPdfFile);
      Files.writeString(outputHtmlFile, reportContent, StandardCharsets.UTF_8);
    }
    log.info("done!");
  }

  public static void createPdf(final String html, final Path outputPdfFile) throws IOException {
    log.info("create pdf file: {}", outputPdfFile);
    final PdfDocument pdfDocument = new PdfDocument(new PdfWriter(outputPdfFile.toFile()));

    pdfDocument.setDefaultPageSize(PageSize.A3.rotate());
    HtmlConverter.convertToPdf(html, pdfDocument, null);
  }

  public static Path prepareReportDirAndGetBaseFilename(final Path logFile) throws IOException {
    final Path reportsDir = Path.of("./out/testreport/");
    if (Files.notExists(reportsDir)) {
      Files.createDirectory(reportsDir);
    }
    return reportsDir.resolve(FilenameUtils.getBaseName(logFile.toString()));
  }

  public static void main(final String[] args) throws IOException {

    final String defaultLogFilename =
        Path.of(ApprovalTestsBase.OUT_LOGS_DIRNAME, "pkits-testsuite-test.log").toString();

    final String logFilename = Objects.toString(ArrayUtils.get(args, 0), defaultLogFilename);

    final Path logFile = Path.of(logFilename);
    final Path baseFilename = prepareReportDirAndGetBaseFilename(logFile);

    final String logContent = Files.readString(logFile, StandardCharsets.UTF_8);

    saveHtmlAndPdf(logContent, baseFilename, true);
  }
}
