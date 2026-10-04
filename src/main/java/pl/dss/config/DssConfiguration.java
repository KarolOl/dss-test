package pl.dss.config;

import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(DssValidationProperties.class)
public class DssConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(DssConfiguration.class);

    @Bean
    @ConditionalOnMissingBean(CertificateVerifier.class)
    CertificateVerifier certificateVerifier(DssValidationProperties properties)
            throws CertificateException, IOException {
        var trusted = new CommonTrustedCertificateSource();
        var certificateFactory = CertificateFactory.getInstance("X.509");
        for (Resource resource : properties.trustedCertificates()) {
            try (InputStream input = resource.getInputStream()) {
                var certificates = certificateFactory.generateCertificates(input);
                if (certificates.isEmpty()) {
                    throw new CertificateException("No certificates in " + resource.getDescription());
                }
                for (var certificate : certificates) {
                    trusted.addCertificate(new CertificateToken((X509Certificate) certificate));
                }
            }
        }
        if (properties.trustedCertificates().isEmpty()) {
            LOG.warn("DSS trust source is empty. Configure explicit trust anchors or provide a CertificateVerifier bean with validated TL/LOTL sources.");
        }

        var crlLoader = new CommonsDataLoader();
        configureTimeouts(crlLoader, properties.networkTimeoutMillis());
        var ocspLoader = new OCSPDataLoader();
        configureTimeouts(ocspLoader, properties.networkTimeoutMillis());
        var verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setAIASource(new DefaultAIASource(crlLoader));
        verifier.setCrlSource(new OnlineCRLSource(crlLoader));
        verifier.setOcspSource(new OnlineOCSPSource(ocspLoader));
        // Keep DSS defaults for trust, timestamp verification, revocation strategy and alerts.
        return verifier;
    }

    @Bean
    @ConditionalOnMissingBean(ValidationPolicy.class)
    ValidationPolicy validationPolicy(DssValidationProperties properties) throws IOException {
        if (properties.policy() == null) {
            return ValidationPolicyLoader.fromDefaultValidationPolicy().create();
        }
        // Load at startup: an invalid/missing configured policy must never silently fall back.
        try (InputStream input = properties.policy().getInputStream()) {
            return ValidationPolicyLoader.fromValidationPolicy(input).create();
        }
    }

    private static void configureTimeouts(CommonsDataLoader loader, int timeout) {
        loader.setTimeoutConnection(timeout);
        loader.setTimeoutConnectionRequest(timeout);
        loader.setTimeoutResponse(timeout);
        loader.setTimeoutSocket(timeout);
    }
}
