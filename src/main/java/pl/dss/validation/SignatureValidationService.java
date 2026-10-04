package pl.dss.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import pl.dss.config.DssValidationProperties;
import pl.dss.validation.model.CompositeValidationReport;
import pl.dss.validation.model.CompositeValidationReport.*;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static pl.dss.validation.DocumentValidationException.Code.*;

@Service
public class SignatureValidationService {
    private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationService.class);

    private final CertificateVerifier certificateVerifier;
    private final ValidationPolicy validationPolicy;
    private final DssValidationProperties properties;
    private final DssReportMapper mapper;

    public SignatureValidationService(CertificateVerifier certificateVerifier, ValidationPolicy validationPolicy,
                                      DssValidationProperties properties, DssReportMapper mapper) {
        this.certificateVerifier = certificateVerifier;
        this.validationPolicy = validationPolicy;
        this.properties = properties;
        this.mapper = mapper;
    }

    /** Detached signatures without their signed content are reported as incomplete by DSS. */
    public CompositeValidationReport validate(MultipartFile file) {
        return validate(file, List.of());
    }

    /** Provide every required original document with its original name for detached references. */
    public CompositeValidationReport validate(MultipartFile file, List<MultipartFile> detachedContents) {
        Upload main = read(file, properties.maxTotalUploadBytes());
        int remaining = properties.maxTotalUploadBytes() - main.bytes().length;
        List<Upload> detached = new ArrayList<>();
        for (MultipartFile content : detachedContents == null ? List.<MultipartFile>of() : detachedContents) {
            Upload upload = read(content, remaining);
            remaining -= upload.bytes().length;
            detached.add(upload);
        }
        detached = List.copyOf(detached);

        // Intentionally no setValidationTime on the initial validator.
        Reports initialReports = run(main, detached, null);
        Instant defaultValidationTime = mapper.validationTime(initialReports);
        Map<String, SignatureResult> initial = initialResults(initialReports);
        List<SignatureEntry> entries = new ArrayList<>(initial.size());
        Map<String, Reports> additionalReports = new LinkedHashMap<>();

        for (var signature : initial.entrySet()) {
            String signatureId = signature.getKey();
            SignatureResult original = signature.getValue();
            RevalidationReason reason = reason(original, defaultValidationTime);
            if (reason != RevalidationReason.NON_PASSED_WITH_BEST_TIME_EQUAL_TO_DEFAULT_AND_DECLARED_SIGNING_TIME) {
                entries.add(new SignatureEntry(signatureId, original, original,
                        new RevalidationAttempt(AttemptStatus.SKIPPED, reason, null, null, null)));
                continue;
            }

            Instant actualTime = null;
            try {
                // DSS 6.5 exposes whole-document validation, not validateSignature(signatureId).
                // Each run creates a new validator and only this signature's entry replaces the initial result.
                Reports revalidated = run(main, detached, original.signingTime());
                additionalReports.put(signatureId, revalidated);
                actualTime = mapper.validationTime(revalidated);
                if (!original.signingTime().equals(actualTime)) {
                    throw new DocumentValidationException(INCONSISTENT_DSS_REPORT,
                            "DSS revalidation time differs from requested signing time");
                }
                SignatureResult effective = mapper.signature(revalidated, signatureId, ResultSource.SIGNING_TIME_REVALIDATION);
                entries.add(new SignatureEntry(signatureId, original, effective,
                        new RevalidationAttempt(AttemptStatus.APPLIED, reason, original.signingTime(), actualTime, null)));
            } catch (RuntimeException exception) {
                // A technical failure is not a DSS signature verdict. Preserve the original result and any returned Reports.
                String code = exception instanceof DocumentValidationException validationException
                        ? validationException.getCode().name() : VALIDATION_ERROR.name();
                LOG.warn("Signing-time revalidation failed for signature {} ({})", signatureId, code, exception);
                entries.add(new SignatureEntry(signatureId, original, original,
                        new RevalidationAttempt(AttemptStatus.TECHNICAL_FAILURE, reason, original.signingTime(), actualTime, code)));
            }
        }

        long validCount = entries.stream().filter(entry -> entry.effective().indication() == Indication.TOTAL_PASSED).count();
        DocumentStatus status = entries.isEmpty() ? DocumentStatus.NO_SIGNATURES : DocumentStatus.ANALYZED;
        if (entries.stream().anyMatch(entry -> entry.effective().signedDataMissing())) {
            status = DocumentStatus.MISSING_SIGNED_DATA;
        }
        return new CompositeValidationReport(main.name(), initialReports.getSimpleReport().getContainerType(),
                status, defaultValidationTime, entries.size(), validCount,
                entries, new OriginalDssReports(initialReports, additionalReports));
    }

    private Map<String, SignatureResult> initialResults(Reports reports) {
        Map<String, SignatureResult> results = new LinkedHashMap<>();
        try {
            List<String> simpleIds = reports.getSimpleReport().getSignatureIdList();
            List<String> diagnosticIds = reports.getDiagnosticData().getSignatureIdList();
            if (new HashSet<>(simpleIds).size() != simpleIds.size()
                    || new HashSet<>(diagnosticIds).size() != diagnosticIds.size()
                    || !new HashSet<>(simpleIds).equals(new HashSet<>(diagnosticIds))) {
                throw new DocumentValidationException(INCONSISTENT_DSS_REPORT,
                        "DSS simple and diagnostic reports have inconsistent signature identifiers");
            }
            for (String id : simpleIds) {
                results.put(id, mapper.signature(reports, id, ResultSource.DEFAULT_VALIDATION));
            }
            return results;
        } catch (DocumentValidationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new DocumentValidationException(INCONSISTENT_DSS_REPORT, "Cannot read DSS report", exception);
        }
    }

    private static RevalidationReason reason(SignatureResult original, Instant defaultTime) {
        if (original.indication() == Indication.TOTAL_PASSED) {
            return RevalidationReason.ALREADY_TOTAL_PASSED;
        }
        if (original.bestSignatureTime() == null) {
            return RevalidationReason.BEST_SIGNATURE_TIME_MISSING;
        }
        if (original.signingTime() == null) {
            return RevalidationReason.SIGNING_TIME_MISSING;
        }
        if (!original.bestSignatureTime().equals(defaultTime)) {
            return RevalidationReason.BEST_SIGNATURE_TIME_DIFFERS_FROM_DEFAULT_VALIDATION_TIME;
        }
        return RevalidationReason.NON_PASSED_WITH_BEST_TIME_EQUAL_TO_DEFAULT_AND_DECLARED_SIGNING_TIME;
    }

    private Reports run(Upload main, List<Upload> detached, Instant validationTime) {
        final SignedDocumentValidator validator;
        try {
            validator = SignedDocumentValidator.fromDocument(main.document());
        } catch (UnsupportedOperationException exception) {
            // A severely corrupted document may be indistinguishable from an unsupported format to DSS factories.
            throw new DocumentValidationException(UNSUPPORTED_OR_UNRECOGNIZED_DOCUMENT,
                    "DSS cannot recognize this document with the installed validation modules", exception);
        } catch (RuntimeException exception) {
            throw new DocumentValidationException(MALFORMED_DOCUMENT, "Cannot parse the document", exception);
        }

        try {
            validator.setCertificateVerifier(certificateVerifier);
            validator.setValidationLevel(properties.level());
            validator.setEnableEtsiValidationReport(true);
            validator.setIncludeSemantics(true);
            validator.setLocale(Locale.ENGLISH);
            validator.setDetachedContents(detached.stream().map(Upload::document).toList());
            if (validationTime != null) {
                validator.setValidationTime(Date.from(validationTime));
            }
        } catch (RuntimeException exception) {
            throw new DocumentValidationException(VALIDATION_ERROR, "Cannot configure DSS validator", exception);
        }

        try {
            validator.getSignatures(); // Parse using DSS; no format/packaging guesses and no signature validity assumptions.
        } catch (RuntimeException exception) {
            throw new DocumentValidationException(MALFORMED_DOCUMENT, "Cannot extract document signatures", exception);
        }
        try {
            // A supplied verifier may contain helpers which store the current ValidationContext.
            // Serialize validation on that verifier rather than share those mutable helpers concurrently.
            synchronized (certificateVerifier) {
                return validator.validateDocument(validationPolicy);
            }
        } catch (RuntimeException exception) {
            throw new DocumentValidationException(VALIDATION_ERROR, "DSS validation failed technically", exception);
        }
    }

    private static Upload read(MultipartFile file, int remainingBytes) {
        if (file == null || file.isEmpty()) {
            throw new DocumentValidationException(EMPTY_FILE, "A non-empty document and non-empty detached contents are required");
        }
        if (file.getSize() > remainingBytes) {
            throw new DocumentValidationException(UPLOAD_TOO_LARGE, "Total upload exceeds configured DSS limit");
        }
        try (InputStream input = file.getInputStream()) {
            byte[] bytes = input.readNBytes(remainingBytes + 1);
            if (bytes.length > remainingBytes) {
                throw new DocumentValidationException(UPLOAD_TOO_LARGE, "Total upload exceeds configured DSS limit");
            }
            if (bytes.length == 0) {
                throw new DocumentValidationException(EMPTY_FILE, "Document stream is empty");
            }
            return new Upload(bytes, filename(file.getOriginalFilename()));
        } catch (IOException exception) {
            throw new DocumentValidationException(FILE_READ_ERROR, "Cannot read uploaded document", exception);
        }
    }

    private static String filename(String supplied) {
        if (supplied == null || supplied.isBlank()) {
            return "document";
        }
        String name = supplied.substring(Math.max(supplied.lastIndexOf('/'), supplied.lastIndexOf('\\')) + 1);
        return name.isBlank() ? "document" : name;
    }

    private record Upload(byte[] bytes, String name) {
        DSSDocument document() {
            // Fresh documents per run; do not let validators share mutable DSSDocument state.
            // The three-argument constructor avoids deriving MIME from the filename.
            return new InMemoryDocument(bytes.clone(), name, null);
        }
    }
}
