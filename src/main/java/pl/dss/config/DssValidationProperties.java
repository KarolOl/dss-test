package pl.dss.config;

import eu.europa.esig.dss.enumerations.ValidationLevel;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.util.List;

@ConfigurationProperties("dss.validation")
public record DssValidationProperties(
        ValidationLevel level,
        List<Resource> trustedCertificates,
        Resource policy,
        int maxTotalUploadBytes,
        int networkTimeoutMillis) {

    public DssValidationProperties {
        level = level == null ? ValidationLevel.ARCHIVAL_DATA : level;
        trustedCertificates = trustedCertificates == null ? List.of() : List.copyOf(trustedCertificates);
        maxTotalUploadBytes = maxTotalUploadBytes == 0 ? 20 * 1024 * 1024 : maxTotalUploadBytes;
        networkTimeoutMillis = networkTimeoutMillis == 0 ? 10_000 : networkTimeoutMillis;
        if (maxTotalUploadBytes < 1 || maxTotalUploadBytes == Integer.MAX_VALUE || networkTimeoutMillis < 1) {
            throw new IllegalArgumentException("DSS upload limit and network timeout must be positive; upload limit must be below Integer.MAX_VALUE");
        }
    }
}
