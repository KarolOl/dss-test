package pl.dss.validation;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import org.springframework.stereotype.Component;
import pl.dss.validation.model.CompositeValidationReport.*;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static pl.dss.validation.DocumentValidationException.Code.INCONSISTENT_DSS_REPORT;

@Component
public class DssReportMapper {
    public SignatureResult signature(Reports reports, String signatureId, ResultSource source) {
        SimpleReport simple = reports.getSimpleReport();
        if (simple.getSignatureIdList().stream().filter(signatureId::equals).count() != 1
                || reports.getDiagnosticData().getSignatureIdList().stream().filter(signatureId::equals).count() != 1
                || simple.getIndication(signatureId) == null) {
            throw new DocumentValidationException(INCONSISTENT_DSS_REPORT,
                    "Missing signature validation result for " + signatureId);
        }
        SignatureWrapper diagnostic = reports.getDiagnosticData().getSignatureById(signatureId);
        if (diagnostic == null) {
            throw new DocumentValidationException(INCONSISTENT_DSS_REPORT,
                    "Missing signature diagnostic data for " + signatureId);
        }
        var level = simple.getSignatureFormat(signatureId);
        var parent = diagnostic.getParent();
        List<ReferenceInfo> references = diagnostic.getDigestMatchers().stream()
                .map(reference -> new ReferenceInfo(reference.getId(), reference.getType(), reference.getUri(),
                        reference.getDocumentName(), reference.isDataFound(), reference.isDataIntact()))
                .toList();
        // DSS evaluates data availability, including detached content. Do not infer it from MIME/extension.
        boolean signedDataMissing = simple.getSubIndication(signatureId) == SubIndication.SIGNED_DATA_NOT_FOUND
                || references.stream().anyMatch(DssReportMapper::missingSignedContent);
        return new SignatureResult(source, validationTime(reports),
                level == null ? null : level.getSignatureForm(), level,
                simple.getSignatureQualification(signatureId), instant(simple.getSigningTime(signatureId)),
                instant(simple.getBestSignatureTime(signatureId)), simple.getIndication(signatureId),
                simple.getSubIndication(signatureId), messages(simple.getAdESValidationErrors(signatureId)),
                messages(simple.getAdESValidationWarnings(signatureId)),
                messages(simple.getQualificationErrors(signatureId)),
                messages(simple.getQualificationWarnings(signatureId)),
                diagnostic.isCounterSignature(), parent == null ? null : parent.getId(),
                certificate(diagnostic.getSigningCertificate()), diagnostic.isTrustedChain(),
                diagnostic.getCertificateChain().stream().map(this::certificate).toList(),
                reports.getDiagnosticData().getTimestampList(signatureId).stream()
                        .map(timestamp -> timestamp(timestamp, simple)).toList(),
                references, signedDataMissing);
    }

    public Instant validationTime(Reports reports) {
        Instant time = instant(reports.getSimpleReport().getValidationTime());
        if (time == null) {
            throw new DocumentValidationException(INCONSISTENT_DSS_REPORT, "DSS report has no document validation time");
        }
        return time;
    }

    private TimestampInfo timestamp(TimestampWrapper timestamp, SimpleReport simple) {
        String id = timestamp.getId();
        return new TimestampInfo(id, timestamp.getType(), instant(timestamp.getProductionTime()),
                simple.getIndication(id), simple.getSubIndication(id), simple.getTimestampQualification(id),
                timestamp.isMessageImprintDataFound(), timestamp.isMessageImprintDataIntact(),
                certificate(timestamp.getSigningCertificate()), messages(simple.getAdESValidationErrors(id)),
                messages(simple.getAdESValidationWarnings(id)));
    }

    private CertificateInfo certificate(CertificateWrapper certificate) {
        if (certificate == null) {
            return null;
        }
        var revocations = certificate.getCertificateRevocationData().stream()
                .map(revocation -> new RevocationInfo(revocation.getId(), revocation.getRevocationType(),
                        revocation.getStatus(), revocation.getReason(), instant(revocation.getRevocationDate()),
                        instant(revocation.getProductionDate()), instant(revocation.getThisUpdate()),
                        instant(revocation.getNextUpdate())))
                .toList();
        return new CertificateInfo(certificate.getId(), certificate.getCertificateDN(),
                certificate.getCertificateIssuerDN(), certificate.getSerialNumber(),
                instant(certificate.getNotBefore()), instant(certificate.getNotAfter()),
                certificate.isTrusted(), revocations);
    }

    private static List<ValidationMessage> messages(List<Message> messages) {
        return messages.stream().map(message -> new ValidationMessage(message.getKey(), message.getValue())).toList();
    }

    private static boolean missingSignedContent(ReferenceInfo reference) {
        if (reference.type() == null || reference.dataFound()) {
            return false;
        }
        return switch (reference.type()) {
            case REFERENCE, OBJECT, MANIFEST, MANIFEST_ENTRY, MESSAGE_DIGEST, CONTENT_DIGEST, SIG_D_ENTRY -> true;
            default -> false;
        };
    }

    private static Instant instant(Date date) {
        // In-memory DSS reports retain Date milliseconds. Do not marshal/reparse XML (DateParser loses fractions).
        return date == null ? null : Instant.ofEpochMilli(date.getTime());
    }
}
