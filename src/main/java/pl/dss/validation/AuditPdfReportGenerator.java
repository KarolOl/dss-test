package pl.dss.validation;

import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.dss.validation.AuditPdfAttachmentService.InputDigest;
import pl.dss.validation.AuditPdfAttachmentService.Manifest;
import pl.dss.validation.model.AuditPdfReport;
import pl.dss.validation.model.CompositeValidationReport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;

import static pl.dss.validation.AuditPdfAttachmentService.sha256;
import static pl.dss.validation.DocumentValidationException.Code.REPORT_GENERATION_ERROR;

/** Export-only: never reruns validation or merges/modifies the original DSS reports. */
@Component
public class AuditPdfReportGenerator {
    private static final Logger LOG = LoggerFactory.getLogger(AuditPdfReportGenerator.class);
    private final AuditPdfAttachmentService attachmentService;

    public AuditPdfReportGenerator(AuditPdfAttachmentService attachmentService) {
        this.attachmentService = attachmentService;
    }

    public AuditPdfReport generate(CompositeValidationReport report, List<InputDigest> inputs,
                                   ValidationPolicy policy, ValidationLevel level) {
        try (var pdf = new PDDocument(); var output = new ByteArrayOutputStream()) {
            var audit = attachmentService.addAttachments(pdf, report, inputs, policy, level);
            var manifest = audit.manifest();
            String manifestHash = audit.manifestSha256();
            pdf.getDocumentInformation().setTitle("Raport weryfikacji podpisów");
            pdf.getDocumentInformation().setCreator("DSS signature-validation");
            render(pdf, report, manifest, manifestHash);
            pdf.save(output);
            byte[] bytes = output.toByteArray();
            String pdfHash = sha256(bytes);
            LOG.info("Generated audit report id={} pdfSha256={} manifestSha256={}", manifest.reportId(), pdfHash, manifestHash);
            return new AuditPdfReport(bytes, pdfHash, manifestHash);
        } catch (IOException | RuntimeException exception) {
            // An incomplete evidence package must not be returned as a successful report.
            throw new DocumentValidationException(REPORT_GENERATION_ERROR,
                    "Cannot create the PDF audit report with all DSS evidence", exception);
        }
    }

    private static void render(PDDocument pdf, CompositeValidationReport report, Manifest manifest,
                               String manifestHash) throws IOException {
        try (var page = new Pages(pdf)) {
            page.heading("Raport weryfikacji podpisów");
            page.text("Identyfikator raportu: " + manifest.reportId());
            page.text("Utworzono (UTC, zegar aplikacji): " + manifest.generatedAt());
            page.text("Dokument: " + report.documentName());
            page.text("Status dokumentu: " + report.documentStatus());
            page.text("Czas pierwszej walidacji (UTC): " + report.defaultValidationTime());
            page.text("Liczba podpisów: " + report.signaturesCount()
                    + "; efektywnych wyników TOTAL_PASSED: " + report.validSignaturesCount());
            page.text("DSS: " + manifest.dssVersion() + "; poziom: " + manifest.validationLevel());
            page.text("Polityka: " + manifest.policyName());
            page.text("Archiwizacja polityki: " + manifest.policyEvidence());
            page.heading("Granice dowodowe raportu");
            page.text("Raport nie jest podpisany ani opieczętowany i nie posiada zaufanego znacznika czasu. "
                    + "SHA-256 pozwala porównać dane, ale nie potwierdza wystawcy ani daty. "
                    + "Zachowaj skrót końcowego PDF w niezależnym, chronionym rejestrze; "
                    + "dla potwierdzenia pochodzenia podpisz lub opieczętuj cały PDF wraz z załącznikami "
                    + "i dodaj zaufany znacznik czasu.");
            page.text("Ocena SIGNING_TIME_REVALIDATION jest warunkowa: deklarowany czas podpisania "
                    + "nie jest zaufanym dowodem istnienia podpisu. Wynik pierwotny pozostaje w załącznikach.");
            page.text("Wejściowe pliki nie są osadzone. Do ponownej analizy zachowaj oryginały oraz "
                    + "konfigurację zaufania, w tym historyczne TL/LOTL, jeśli były użyte. "
                    + "Jeśli polityka ma status IDENTITY_ONLY, zachowaj też jej efektywną konfigurację. "
                    + "Diagnostyka zawiera dostępne dane binarne użyte przez DSS, a nie gwarancję pełnego archiwum.");
            page.heading("Dokumenty wejściowe (SHA-256)");
            for (var input : manifest.inputs()) {
                page.text(input.role() + " [" + input.index() + "]: " + input.name() + " (" + input.size() + " B)");
                page.text(input.sha256());
            }
            for (var entry : report.signatures()) {
                page.heading("Podpis: " + entry.signatureId());
                var result = entry.effective();
                page.text("Pierwotny wynik DSS: " + entry.original().indication() + " / " + entry.original().subIndication());
                page.text("Efektywny wynik: " + result.indication() + " / " + result.subIndication());
                page.text("Źródło: " + result.source() + "; czas walidacji: " + result.validationTime());
                page.text("Format: " + result.level() + "; kwalifikacja: " + result.qualification());
                if (result.signingCertificate() != null) {
                    page.text("Podpisujący: " + result.signingCertificate().subject());
                    page.text("Numer seryjny certyfikatu: " + result.signingCertificate().serialNumber());
                }
                page.text("Deklarowany czas podpisania: " + result.signingTime());
                page.text("Best signature time: " + result.bestSignatureTime());
                page.text("Brak podpisanych danych: " + result.signedDataMissing());
                var attempt = entry.revalidation();
                page.text("Dodatkowy przebieg: " + attempt.status() + "; powód: " + attempt.reason());
                if (attempt.requestedValidationTime() != null) {
                    page.text("Żądany czas: " + attempt.requestedValidationTime() + "; czas DSS: " + attempt.actualValidationTime());
                }
                if (attempt.technicalErrorCode() != null) {
                    page.text("Błąd techniczny: " + attempt.technicalErrorCode());
                }
                for (var error : result.errors()) page.text("Błąd: " + error.key() + " - " + error.text());
                for (var warning : result.warnings()) page.text("Ostrzeżenie: " + warning.key() + " - " + warning.text());
            }
            page.heading("Pakiet audytowy");
            page.text("Załączniki otworzysz w panelu załączników czytnika PDF. "
                    + "audit-manifest.json opisuje przebiegi i skróty dokładnych bajtów pozostałych załączników. "
                    + "composite-report.json zachowuje mapowanie wyników i precyzję czasu obiektów Java; "
                    + "XML DSS może zapisywać czas z precyzją sekund.");
            page.text("SHA-256 audit-manifest.json: " + manifestHash);
            for (var run : manifest.runs()) {
                page.text("Przebieg " + run.id() + "; podpis docelowy: " + Objects.toString(run.targetSignatureId(), "cały dokument")
                        + "; czas DSS: " + run.validationTime());
            }
            for (var attachment : manifest.attachments()) {
                page.text(attachment.name() + " (" + attachment.size() + " B)");
                page.text(attachment.sha256());
            }
        }
    }

    /** Embedded Unicode font, width-aware wrapping (including long IDs), and page breaks. */
    private static final class Pages implements AutoCloseable {
        private static final float MARGIN = 48;
        private final PDDocument pdf;
        private final PDType0Font font;
        private PDPageContentStream stream;
        private float y;

        private Pages(PDDocument pdf) throws IOException {
            this.pdf = pdf;
            try (InputStream input = Objects.requireNonNull(AuditPdfReportGenerator.class
                    .getResourceAsStream("/fonts/LiberationSans-Regular.ttf"), "Missing report font")) {
                font = PDType0Font.load(pdf, input);
            }
        }

        void heading(String text) throws IOException {
            if (stream != null) y -= 12;
            if (stream == null || y < 105) newPage();
            write(text, 13);
            y -= 4;
        }

        void text(String text) throws IOException {
            write(text, 10);
        }

        private void write(String value, float size) throws IOException {
            StringBuilder line = new StringBuilder();
            float width = 0;
            for (int codePoint : value.codePoints().toArray()) {
                String character = Character.isISOControl(codePoint) ? " " : new String(Character.toChars(codePoint));
                try {
                    font.encode(character);
                } catch (IllegalArgumentException unsupported) {
                    // Exact Unicode text remains in JSON; do not silently lose characters in the PDF.
                    character = "[U+" + Integer.toHexString(codePoint).toUpperCase(java.util.Locale.ROOT) + "]";
                }
                float characterWidth = font.getStringWidth(character) * size / 1000;
                while (width + characterWidth > PDRectangle.A4.getWidth() - 2 * MARGIN && !line.isEmpty()) {
                    int space = line.lastIndexOf(" ");
                    if (space > 0) {
                        line(line.substring(0, space), size);
                        line.delete(0, space + 1);
                        width = font.getStringWidth(line.toString()) * size / 1000;
                    } else {
                        line(line.toString(), size);
                        line.setLength(0);
                        width = 0;
                    }
                }
                line.append(character);
                width += characterWidth;
            }
            if (!line.isEmpty()) line(line.toString(), size);
            y -= 4;
        }

        private void line(String text, float size) throws IOException {
            if (stream == null || y < 65) newPage();
            stream.beginText();
            stream.setFont(font, size);
            stream.newLineAtOffset(MARGIN, y);
            stream.showText(text);
            stream.endText();
            y -= size + 5;
        }

        private void newPage() throws IOException {
            if (stream != null) stream.close();
            var page = new PDPage(PDRectangle.A4);
            pdf.addPage(page);
            stream = new PDPageContentStream(pdf, page);
            stream.beginText();
            stream.setFont(font, 9);
            stream.newLineAtOffset(MARGIN, 30);
            stream.showText("Raport weryfikacji podpisów | Strona " + pdf.getNumberOfPages());
            stream.endText();
            y = PDRectangle.A4.getHeight() - MARGIN;
        }

        @Override
        public void close() throws IOException {
            if (stream != null) stream.close();
        }
    }
}
