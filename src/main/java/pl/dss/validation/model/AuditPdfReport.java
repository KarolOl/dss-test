package pl.dss.validation.model;

/** Hashes identify the exact exported bytes; they are not a signature or a trusted timestamp. */
public record AuditPdfReport(byte[] bytes, String sha256, String manifestSha256) {
    public AuditPdfReport {
        bytes = bytes.clone();
    }

    @Override
    public byte[] bytes() {
        return bytes.clone();
    }
}
