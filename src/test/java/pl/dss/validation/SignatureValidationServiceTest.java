package pl.dss.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.mock.web.MockMultipartFile;
import pl.dss.config.DssValidationProperties;
import pl.dss.config.ArchivedValidationPolicy;
import pl.dss.validation.model.CompositeValidationReport;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import tools.jackson.databind.json.JsonMapper;

import static org.junit.jupiter.api.Assertions.*;
import static pl.dss.validation.model.CompositeValidationReport.*;

/** Exercises the public MultipartFile method with real DSS validation, without a Spring context. */
class SignatureValidationServiceTest {
    private static TwoSignatureDocument document;

    @BeforeAll
    static void createSignedDocument() throws Exception {
        document = TwoSignatureDocument.create();
        assertEquals(2, document.signedData().getSignerInfos().size(),
                "The fixture must actually contain two cryptographic signatures");
    }

    @Test
    void validatesEverySignatureAndPreservesOriginalReports() throws Exception {
        CompositeValidationReport report = service().validate(upload(document.encoded()));

        assertEquals(DocumentStatus.ANALYZED, report.documentStatus());
        assertEquals(2, report.signaturesCount());
        assertEquals(2, report.signatures().size());
        assertEquals(2L, report.validSignaturesCount());
        var signatureIds = report.signatures().stream().map(SignatureEntry::signatureId).toList();
        assertEquals(2, new HashSet<>(signatureIds).size());
        assertEquals(new HashSet<>(signatureIds), new HashSet<>(
                report.originalDssReports().defaultValidation().getSimpleReport().getSignatureIdList()));
        assertEquals(report.originalDssReports().defaultValidation().getSimpleReport()
                .getValidationTime().toInstant(), report.defaultValidationTime());
        assertTrue(report.originalDssReports().revalidationsBySignatureId().isEmpty());
        assertEquals(document.signingTimesByCertificateSerial().keySet(), new HashSet<>(
                report.signatures().stream().map(entry -> entry.effective().signingCertificate().serialNumber()).toList()));

        // Match signers by certificate serial, never by the order of CMS SignerInfos or DSS results.
        for (SignatureEntry entry : report.signatures()) {
            SignatureResult result = entry.effective();
            assertEquals(Indication.TOTAL_PASSED, result.indication());
            assertEquals(SignatureForm.CAdES, result.format());
            assertEquals(ResultSource.DEFAULT_VALIDATION, result.source());
            assertSame(entry.original(), result);
            assertEquals(report.defaultValidationTime(), result.validationTime());
            assertEquals(report.defaultValidationTime(), result.bestSignatureTime());
            assertEquals(document.signingTimesByCertificateSerial().get(result.signingCertificate().serialNumber()),
                    result.signingTime());
            assertTrue(result.trustedChain());
            assertTrue(result.errors().isEmpty());
            assertFalse(result.signedDataMissing());
            assertFalse(result.counterSignature());
            assertNull(result.parentSignatureId());
            assertTrue(result.timestamps().isEmpty());
            assertEquals(AttemptStatus.SKIPPED, entry.revalidation().status());
            assertEquals(RevalidationReason.ALREADY_TOTAL_PASSED, entry.revalidation().reason());
        }
    }

    @Test
    void rejectsBothSignaturesWhenSignedContentIsTamperedWith() throws Exception {
        CompositeValidationReport report = service().validate(upload(document.withTamperedContent()));

        assertEquals(DocumentStatus.ANALYZED, report.documentStatus());
        assertEquals(2, report.signaturesCount());
        assertEquals(2, report.signatures().size());
        assertEquals(0L, report.validSignaturesCount());
        for (SignatureEntry entry : report.signatures()) {
            assertEquals(Indication.TOTAL_FAILED, entry.original().indication());
            assertEquals(SubIndication.HASH_FAILURE, entry.original().subIndication());
            assertEquals(Indication.TOTAL_FAILED, entry.effective().indication());
            assertEquals(SubIndication.HASH_FAILURE, entry.effective().subIndication());
            assertFalse(entry.effective().errors().isEmpty());
            assertFalse(entry.effective().signedDataMissing());
            assertTrue(entry.effective().references().stream()
                    .anyMatch(reference -> reference.dataFound() && !reference.dataIntact()));
            assertNotEquals(AttemptStatus.TECHNICAL_FAILURE, entry.revalidation().status(),
                    "An invalid signature must be a DSS verdict, not a technical exception");
        }
        var attachments = evidence(report);
        var manifest = manifest(attachments);
        assertEquals(1 + report.originalDssReports().revalidationsBySignatureId().size(), manifest.runs().size());
        assertRunXml(attachments, "default", report.originalDssReports().defaultValidation());
        for (var run : manifest.runs()) {
            if (run.targetSignatureId() != null) {
                var dssRun = report.originalDssReports().revalidationsBySignatureId().get(run.targetSignatureId());
                assertNotNull(dssRun);
                assertRunXml(attachments, run.id(), dssRun);
            }
        }
    }

    @Test
    void generatesPdfWithOriginalDssEvidenceAndVerifiableManifest() throws Exception {
        byte[] input = document.encoded();
        CompositeValidationReport report = service().validate(upload(input));

        assertNotNull(report.pdfReport());
        byte[] pdfBytes = report.pdfReport().bytes();
        assertEquals(digest(pdfBytes), report.pdfReport().sha256());
        var attachments = evidence(report);
        var manifest = manifest(attachments);
        assertEquals("UNSEALED", manifest.authenticity());
        assertEquals("SHA-256", manifest.digestAlgorithm());
        assertEquals("6.5", manifest.dssVersion());
        assertEquals(1, manifest.schemaVersion());
        assertEquals(1, manifest.inputs().size());
        assertEquals("DOCUMENT", manifest.inputs().getFirst().role());
        assertEquals(input.length, manifest.inputs().getFirst().size());
        assertEquals(digest(input), manifest.inputs().getFirst().sha256());
        assertEquals(1, manifest.runs().size());
        assertNull(manifest.runs().getFirst().targetSignatureId());
        assertEquals(report.defaultValidationTime(), manifest.runs().getFirst().validationTime());
        assertEquals(5, attachments.size());
        assertNull(report.originalDssReports().defaultValidation().getEtsiValidationReportJaxb(),
                "The unused ETSI report should not be generated");
        assertEquals("XML_SNAPSHOT: validation-policy.xml", manifest.policyEvidence());
        assertArrayEquals(ArchivedValidationPolicy.loadDefault().xml(), attachments.get("validation-policy.xml"));
        assertRunXml(attachments, "default", report.originalDssReports().defaultValidation());
        var diagnostic = report.originalDssReports().defaultValidation().getDiagnosticDataJaxb();
        assertTrue(diagnostic.getUsedCertificates().stream().allMatch(certificate ->
                certificate.getBase64Encoded() != null && certificate.getBase64Encoded().length > 0));
        assertFalse(diagnostic.getUsedRevocations().isEmpty());
        assertTrue(diagnostic.getUsedRevocations().stream().allMatch(revocation ->
                revocation.getBase64Encoded() != null && revocation.getBase64Encoded().length > 0));

        var json = JsonMapper.builder().build();
        var composite = json.readTree(attachments.get("composite-report.json"));
        assertEquals(2, composite.get("signaturesCount").asInt());
        assertFalse(composite.has("originalDssReports"));
        assertFalse(composite.has("pdfReport"));
        var exported = json.readValue(attachments.get("composite-report.json"), CompositeValidationReport.class);
        assertEquals(report.defaultValidationTime(), exported.defaultValidationTime());
        assertEquals(report.signatures(), exported.signatures(), "JSON must preserve complete results and Java time precision");
        // The PDF must not expose an array that a caller can change after hashes have been assigned.
        pdfBytes[0] ^= 1;
        assertEquals(digest(report.pdfReport().bytes()), report.pdfReport().sha256());

        Path output = Path.of(System.getProperty("dss.test.reportPath", "target/test-reports/signature-validation-audit.pdf"));
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.write(output, report.pdfReport().bytes());
    }

    @Test
    void bindsDetachedContentToItsExactBytesAndPreservesUnicodeNames() throws Exception {
        byte[] signature = document.detached();
        byte[] content = document.content();
        var original = new MockMultipartFile("detachedContents", "zażółć-gęślą.txt", "text/plain", content);
        var report = service().validate(upload(signature), List.of(original));

        assertEquals(2L, report.validSignaturesCount());
        var attachments = evidence(report);
        var manifest = manifest(attachments);
        assertEquals(2, manifest.inputs().size());
        assertEquals(digest(signature), manifest.inputs().getFirst().sha256());
        var detached = manifest.inputs().get(1);
        assertEquals("DETACHED_CONTENT", detached.role());
        assertEquals(0, detached.index());
        assertEquals("zażółć-gęślą.txt", detached.name());
        assertEquals(digest(content), detached.sha256());
        assertEquals(content.length, detached.size());
        // Evidence is XML/JSON only; confidential source files are retained outside the PDF.
        assertTrue(attachments.keySet().stream().allMatch(name -> name.endsWith(".xml") || name.endsWith(".json")));
        try (var pdf = Loader.loadPDF(report.pdfReport().bytes())) {
            assertTrue(new PDFTextStripper().getText(pdf).contains("zażółć-gęślą.txt"));
        }
    }

    @Test
    void generatesAnAuditPackageForARecognizedDocumentWithoutSignatures() throws Exception {
        byte[] input;
        try (var unsigned = new org.apache.pdfbox.pdmodel.PDDocument();
             var output = new java.io.ByteArrayOutputStream()) {
            unsigned.addPage(new org.apache.pdfbox.pdmodel.PDPage());
            unsigned.save(output);
            input = output.toByteArray();
        }

        var report = service().validate(upload(input));

        assertEquals(DocumentStatus.NO_SIGNATURES, report.documentStatus());
        assertEquals(0, report.signaturesCount());
        assertEquals(0L, report.validSignaturesCount());
        var attachments = evidence(report);
        assertRunXml(attachments, "default", report.originalDssReports().defaultValidation());
        assertEquals(digest(input), manifest(attachments).inputs().getFirst().sha256());
    }

    @Test
    void preservesReturnedRevalidationEvidenceEvenForTechnicalFailure() throws Exception {
        var original = service().validate(upload(document.encoded()));
        var first = original.signatures().getFirst();
        var failed = new SignatureEntry(first.signatureId(), first.original(), first.original(),
                new RevalidationAttempt(AttemptStatus.TECHNICAL_FAILURE,
                        RevalidationReason.NON_PASSED_WITH_BEST_TIME_EQUAL_TO_DEFAULT_AND_DECLARED_SIGNING_TIME,
                        first.original().signingTime(), original.defaultValidationTime(), "INCONSISTENT_DSS_REPORT"));
        // Deliberately retain a run with a mismatched time, as the service does on a technical failure.
        // These are actual DSS reports; only the application's attempt metadata is constructed here.
        var report = new CompositeValidationReport(original.documentName(), original.containerType(),
                original.documentStatus(), original.defaultValidationTime(), 2, 2,
                List.of(failed, original.signatures().get(1)),
                new OriginalDssReports(original.originalDssReports().defaultValidation(),
                        Map.of(first.signatureId(), original.originalDssReports().defaultValidation())), null);
        var generated = new AuditPdfReportGenerator(new AuditPdfAttachmentService()).generate(report,
                List.of(AuditPdfAttachmentService.InputDigest.of("DOCUMENT", 0, report.documentName(), document.encoded())),
                ValidationPolicyLoader.fromDefaultValidationPolicy().create(),
                eu.europa.esig.dss.enumerations.ValidationLevel.ARCHIVAL_DATA);
        report = report.withPdfReport(generated);

        var attachments = evidence(report);
        var manifest = manifest(attachments);
        assertEquals(6, attachments.size());
        assertEquals(2, manifest.runs().size());
        assertEquals(first.signatureId(), manifest.runs().get(1).targetSignatureId());
        assertRunXml(attachments, "revalidation-1", original.originalDssReports().defaultValidation());
        try (var pdf = Loader.loadPDF(generated.bytes())) {
            String text = new PDFTextStripper().getText(pdf);
            assertTrue(text.contains("TECHNICAL_FAILURE"));
            assertTrue(text.contains("INCONSISTENT_DSS_REPORT"));
        }
    }

    @Test
    void refusesToReturnPdfWhenAnyEvidenceCannotBeSerialized() throws Exception {
        var original = service().validate(upload(document.encoded()));
        var dss = original.originalDssReports().defaultValidation();
        var broken = new eu.europa.esig.dss.validation.reports.Reports(dss.getDiagnosticDataJaxb(),
                dss.getDetailedReportJaxb(), dss.getSimpleReportJaxb(), dss.getEtsiValidationReportJaxb()) {
            @Override
            public String getXmlDetailedReport() {
                throw new IllegalStateException("serialization failed");
            }
        };
        var report = new CompositeValidationReport(original.documentName(), original.containerType(),
                original.documentStatus(), original.defaultValidationTime(), 2, 2, original.signatures(),
                new OriginalDssReports(broken, Map.of()), null);

        var exception = assertThrows(DocumentValidationException.class, () -> new AuditPdfReportGenerator(new AuditPdfAttachmentService()).generate(
                report, List.of(), ValidationPolicyLoader.fromDefaultValidationPolicy().create(),
                eu.europa.esig.dss.enumerations.ValidationLevel.ARCHIVAL_DATA));
        assertEquals(DocumentValidationException.Code.REPORT_GENERATION_ERROR, exception.getCode());
    }

    private static Map<String, byte[]> evidence(CompositeValidationReport report) throws Exception {
        var result = new TreeMap<String, byte[]>();
        try (var pdf = Loader.loadPDF(report.pdfReport().bytes())) {
            assertTrue(pdf.getNumberOfPages() > 0);
            assertEquals(org.apache.pdfbox.pdmodel.PageMode.USE_NONE, pdf.getDocumentCatalog().getPageMode(),
                    "The attachments panel must not open automatically");
            String text = new PDFTextStripper().getText(pdf);
            assertTrue(text.contains("Raport weryfikacji podpisów"));
            assertTrue(text.contains("Liczba podpisów:"));
            assertTrue(text.contains(report.pdfReport().manifestSha256()));
            var files = pdf.getDocumentCatalog().getNames().getEmbeddedFiles().getNames();
            for (var entry : files.entrySet()) {
                assertEquals(entry.getKey(), entry.getValue().getFileUnicode());
                result.put(entry.getKey(), entry.getValue().getEmbeddedFileUnicode().toByteArray());
            }
            assertTrue(result.keySet().stream().noneMatch(name -> name.endsWith("simple-report.xml")
                    || name.endsWith("etsi-validation-report.xml")), "Redundant DSS reports must not be embedded");
            assertEquals(digest(result.get("audit-manifest.json")), report.pdfReport().manifestSha256());
            assertEquals(report.pdfReport().manifestSha256(),
                    pdf.getDocumentInformation().getCustomMetadataValue("AuditManifestSHA256"));
            assertEquals(manifest(result).reportId(), pdf.getDocumentInformation().getCustomMetadataValue("AuditReportId"));
        }
        var inventory = manifest(result).attachments();
        for (var run : manifest(result).runs()) {
            assertEquals(List.of("dss-" + run.id() + "-detailed-report.xml", "dss-" + run.id() + "-diagnostic-data.xml"),
                    run.attachments(), "Each run must preserve both evidence and its original decision trace");
        }
        var names = new HashSet<String>();
        for (var attachment : inventory) {
            assertTrue(names.add(attachment.name()), "The manifest must not contain duplicate names");
            byte[] bytes = result.get(attachment.name());
            assertNotNull(bytes);
            assertEquals(bytes.length, attachment.size());
            assertEquals(digest(bytes), attachment.sha256());
        }
        names.add("audit-manifest.json");
        assertEquals(result.keySet(), names, "Every attachment must be accounted for");
        return result;
    }

    private static AuditPdfAttachmentService.Manifest manifest(Map<String, byte[]> attachments) {
        return JsonMapper.builder().build().readValue(attachments.get("audit-manifest.json"), AuditPdfAttachmentService.Manifest.class);
    }

    private static void assertRunXml(Map<String, byte[]> attachments, String id,
                                     eu.europa.esig.dss.validation.reports.Reports reports) {
        String prefix = "dss-" + id + "-";
        assertArrayEquals(reports.getXmlDetailedReport().getBytes(StandardCharsets.UTF_8), attachments.get(prefix + "detailed-report.xml"));
        assertArrayEquals(reports.getXmlDiagnosticData().getBytes(StandardCharsets.UTF_8), attachments.get(prefix + "diagnostic-data.xml"));
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static SignatureValidationService service() throws java.io.IOException {
        var trustedCertificates = new CommonTrustedCertificateSource();
        trustedCertificates.addCertificate(document.trustAnchor());
        // All certificates and a fresh CA CRL are embedded; no OCSP/CRL/AIA network calls are needed.
        var verifier = new CommonCertificateVerifier(true);
        verifier.setTrustedCertSources(trustedCertificates);
        return new SignatureValidationService(verifier,
                ArchivedValidationPolicy.loadDefault(),
                new DssValidationProperties(null, List.of(), null, 0, 0), new DssReportMapper(),
                new AuditPdfReportGenerator(new AuditPdfAttachmentService()));
    }

    private static MockMultipartFile upload(byte[] bytes) {
        // Generic name and MIME also exercise DSS format detection.
        return new MockMultipartFile("file", "two-signatures.bin", "application/octet-stream", bytes);
    }
}
