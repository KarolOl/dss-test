package pl.dss.validation;

import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDEmbeddedFilesNameTreeNode;
import org.apache.pdfbox.pdmodel.PageMode;
import org.apache.pdfbox.pdmodel.common.filespecification.PDComplexFileSpecification;
import org.apache.pdfbox.pdmodel.common.filespecification.PDEmbeddedFile;
import org.springframework.stereotype.Service;
import pl.dss.config.ArchivedValidationPolicy;
import pl.dss.validation.model.CompositeValidationReport;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.TreeMap;
import java.util.UUID;

/** Prepares and embeds the complete audit evidence in a new, unsaved report PDF. */
@Service
public class AuditPdfAttachmentService {
    private final JsonMapper json = JsonMapper.builder().build();

    public AttachedAuditData addAttachments(PDDocument pdf, CompositeValidationReport report, List<InputDigest> inputs,
                                             ValidationPolicy policy, ValidationLevel level) throws IOException {
        var attachments = new TreeMap<String, Attachment>();
        var runs = new ArrayList<Run>();
        runs.add(addRun(attachments, "default", null, report.originalDssReports().defaultValidation()));
        var revalidations = report.originalDssReports().revalidationsBySignatureId().entrySet().stream()
                .sorted(Comparator.comparing(java.util.Map.Entry::getKey)).toList();
        for (int i = 0; i < revalidations.size(); i++) {
            var entry = revalidations.get(i);
            // Filenames are generated internally; signature identifiers are data, never paths.
            runs.add(addRun(attachments, "revalidation-" + (i + 1), entry.getKey(), entry.getValue()));
        }
        attachments.put("composite-report.json", new Attachment("application/json", jsonBytes(report)));
        boolean policyArchived = policy instanceof ArchivedValidationPolicy;
        if (policy instanceof ArchivedValidationPolicy archived) {
            attachments.put("validation-policy.xml", new Attachment("application/xml", archived.xml()));
        }
        String reportId = UUID.randomUUID().toString();
        var manifest = new Manifest(1, reportId, Instant.now(), "SHA-256", "UNSEALED",
                version("eu.europa.ec.joinup.sd-dss", "dss-validation"),
                version("pl.dss", "signature-validation"), level.name(),
                policy.getClass().getName(), policy.getPolicyName(), policy.getPolicyDescription(),
                policyArchived ? "XML_SNAPSHOT: validation-policy.xml"
                        : "IDENTITY_ONLY: externally supplied policy; archive its effective configuration separately",
                "DSS_XML_SERIALIZATION_SECONDS; COMPOSITE_JSON_PRESERVES_JAVA_INSTANT_PRECISION",
                List.copyOf(inputs), List.copyOf(runs), attachments.entrySet().stream()
                .map(entry -> new AttachmentDigest(entry.getKey(), entry.getValue().mediaType(),
                        entry.getValue().bytes().length, sha256(entry.getValue().bytes()))).toList());
        byte[] manifestBytes = jsonBytes(manifest);
        String manifestHash = sha256(manifestBytes);
        // No circular hash: the manifest inventories payloads, not itself or the enclosing PDF.
        attachments.put("audit-manifest.json", new Attachment("application/json", manifestBytes));

        embed(pdf, attachments);
        pdf.getDocumentInformation().setCustomMetadataValue("AuditReportId", reportId);
        pdf.getDocumentInformation().setCustomMetadataValue("AuditManifestSHA256", manifestHash);
        return new AttachedAuditData(manifest, manifestHash);
    }

    private byte[] jsonBytes(Object value) {
        return json.writerWithDefaultPrettyPrinter().writeValueAsBytes(value);
    }

    private static Run addRun(TreeMap<String, Attachment> attachments, String id, String signatureId, Reports reports) {
        String prefix = "dss-" + id + "-";
        // Preserve evidence and the original decision trace; summaries already exist in PDF/JSON.
        List<String> names = List.of(prefix + "detailed-report.xml", prefix + "diagnostic-data.xml");
        List<String> xml = List.of(reports.getXmlDetailedReport(), reports.getXmlDiagnosticData());
        for (int i = 0; i < names.size(); i++) {
            if (xml.get(i).isBlank()) {
                throw new IllegalStateException("Missing DSS report: " + names.get(i));
            }
            attachments.put(names.get(i), new Attachment("application/xml", xml.get(i).getBytes(StandardCharsets.UTF_8)));
        }
        var time = reports.getSimpleReport().getValidationTime();
        return new Run(id, signatureId, time == null ? null : time.toInstant(), names);
    }

    private static void embed(PDDocument pdf, TreeMap<String, Attachment> attachments) throws IOException {
        var files = new TreeMap<String, PDComplexFileSpecification>();
        for (var entry : attachments.entrySet()) {
            var spec = new PDComplexFileSpecification();
            spec.setFile(entry.getKey());
            spec.setFileUnicode(entry.getKey());
            spec.setFileDescription("Audit evidence: " + entry.getKey());
            var embedded = new PDEmbeddedFile(pdf, new ByteArrayInputStream(entry.getValue().bytes()));
            embedded.setSubtype(entry.getValue().mediaType());
            embedded.setSize(entry.getValue().bytes().length);
            spec.setEmbeddedFile(embedded);
            spec.setEmbeddedFileUnicode(embedded);
            files.put(entry.getKey(), spec);
        }
        var tree = new PDEmbeddedFilesNameTreeNode();
        tree.setNames(files);
        var names = new PDDocumentNameDictionary(pdf.getDocumentCatalog());
        names.setEmbeddedFiles(tree);
        pdf.getDocumentCatalog().setNames(names);
        pdf.getDocumentCatalog().setPageMode(PageMode.USE_NONE);
    }

    public static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static String version(String group, String artifact) throws IOException {
        try (InputStream input = Reports.class.getResourceAsStream("/META-INF/maven/" + group + "/" + artifact + "/pom.properties")) {
            if (input == null) return "unknown";
            var properties = new Properties();
            properties.load(input);
            return properties.getProperty("version", "unknown");
        }
    }

    public record AttachedAuditData(Manifest manifest, String manifestSha256) { }

    public record InputDigest(String role, int index, String name, long size, String sha256) {
        public static InputDigest of(String role, int index, String name, byte[] bytes) {
            return new InputDigest(role, index, name, bytes.length, AuditPdfAttachmentService.sha256(bytes));
        }
    }

    public record AttachmentDigest(String name, String mediaType, long size, String sha256) { }
    public record Run(String id, String targetSignatureId, Instant validationTime, List<String> attachments) { }
    public record Manifest(int schemaVersion, String reportId, Instant generatedAt, String digestAlgorithm,
                           String authenticity, String dssVersion, String applicationVersion, String validationLevel,
                           String policyClass, String policyName, String policyDescription, String policyEvidence,
                           String timePrecision, List<InputDigest> inputs, List<Run> runs,
                           List<AttachmentDigest> attachments) { }
    private record Attachment(String mediaType, byte[] bytes) { }
}
