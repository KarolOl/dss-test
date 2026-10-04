package pl.dss.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import pl.dss.config.DssValidationProperties;
import pl.dss.validation.model.CompositeValidationReport;

import java.util.HashSet;
import java.util.List;

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
    }

    private static SignatureValidationService service() {
        var trustedCertificates = new CommonTrustedCertificateSource();
        trustedCertificates.addCertificate(document.trustAnchor());
        // All certificates and a fresh CA CRL are embedded; no OCSP/CRL/AIA network calls are needed.
        var verifier = new CommonCertificateVerifier(true);
        verifier.setTrustedCertSources(trustedCertificates);
        return new SignatureValidationService(verifier,
                ValidationPolicyLoader.fromDefaultValidationPolicy().create(),
                new DssValidationProperties(null, List.of(), null, 0, 0), new DssReportMapper());
    }

    private static MockMultipartFile upload(byte[] bytes) {
        // Generic name and MIME also exercise DSS format detection.
        return new MockMultipartFile("file", "two-signatures.bin", "application/octet-stream", bytes);
    }
}
