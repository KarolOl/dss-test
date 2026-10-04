package pl.dss.validation.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.validation.reports.Reports;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Application composite; no DSS report is rewritten or combined with another run. */
public record CompositeValidationReport(
        String documentName,
        ASiCContainerType containerType,
        DocumentStatus documentStatus,
        Instant defaultValidationTime,
        int signaturesCount,
        long validSignaturesCount,
        List<SignatureEntry> signatures,
        @JsonIgnore OriginalDssReports originalDssReports) {

    public CompositeValidationReport {
        signatures = List.copyOf(signatures);
    }

    public enum DocumentStatus { ANALYZED, NO_SIGNATURES, MISSING_SIGNED_DATA }
    public enum ResultSource { DEFAULT_VALIDATION, SIGNING_TIME_REVALIDATION }
    public enum AttemptStatus { SKIPPED, APPLIED, TECHNICAL_FAILURE }
    public enum RevalidationReason {
        ALREADY_TOTAL_PASSED,
        BEST_SIGNATURE_TIME_MISSING,
        SIGNING_TIME_MISSING,
        BEST_SIGNATURE_TIME_DIFFERS_FROM_DEFAULT_VALIDATION_TIME,
        NON_PASSED_WITH_BEST_TIME_EQUAL_TO_DEFAULT_AND_DECLARED_SIGNING_TIME
    }

    public record SignatureEntry(
            String signatureId,
            SignatureResult original,
            SignatureResult effective,
            RevalidationAttempt revalidation) { }

    public record RevalidationAttempt(
            AttemptStatus status,
            RevalidationReason reason,
            Instant requestedValidationTime,
            Instant actualValidationTime,
            String technicalErrorCode) { }

    public record SignatureResult(
            ResultSource source,
            Instant validationTime,
            SignatureForm format,
            SignatureLevel level,
            SignatureQualification qualification,
            Instant signingTime,
            Instant bestSignatureTime,
            Indication indication,
            SubIndication subIndication,
            List<ValidationMessage> errors,
            List<ValidationMessage> warnings,
            List<ValidationMessage> qualificationErrors,
            List<ValidationMessage> qualificationWarnings,
            boolean counterSignature,
            String parentSignatureId,
            CertificateInfo signingCertificate,
            boolean trustedChain,
            List<CertificateInfo> certificateChain,
            List<TimestampInfo> timestamps,
            List<ReferenceInfo> references,
            boolean signedDataMissing) { }

    public record ValidationMessage(String key, String text) { }

    /** Diagnostic trust/revocation facts; they are not an independent certificate validity verdict. */
    public record CertificateInfo(
            String certificateId,
            String subject,
            String issuer,
            String serialNumber,
            Instant notBefore,
            Instant notAfter,
            boolean trustAnchor,
            List<RevocationInfo> revocationData) { }

    public record RevocationInfo(
            String revocationId,
            RevocationType type,
            CertificateStatus status,
            RevocationReason reason,
            Instant revocationTime,
            Instant productionTime,
            Instant thisUpdate,
            Instant nextUpdate) { }

    public record TimestampInfo(
            String timestampId,
            TimestampType type,
            Instant productionTime,
            Indication indication,
            SubIndication subIndication,
            TimestampQualification qualification,
            boolean messageImprintDataFound,
            boolean messageImprintDataIntact,
            CertificateInfo signingCertificate,
            List<ValidationMessage> errors,
            List<ValidationMessage> warnings) { }

    public record ReferenceInfo(
            String referenceId,
            DigestMatcherType type,
            String uri,
            String documentName,
            boolean dataFound,
            boolean dataIntact) { }

    /** Request-owned original objects; callers should treat the mutable DSS Reports as read-only. */
    public record OriginalDssReports(Reports defaultValidation, Map<String, Reports> revalidationsBySignatureId) {
        public OriginalDssReports {
            revalidationsBySignatureId = Map.copyOf(revalidationsBySignatureId);
        }
    }
}
