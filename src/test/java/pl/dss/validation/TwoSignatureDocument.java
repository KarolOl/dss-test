package pl.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

/** Real encapsulated CAdES signatures, generated locally without network or global provider changes. */
record TwoSignatureDocument(CMSSignedData signedData, CertificateToken trustAnchor,
                            Map<String, Instant> signingTimesByCertificateSerial) {

    static TwoSignatureDocument create() throws Exception {
        Provider provider = new BouncyCastleProvider();
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        KeyPair rootKeys = keyPair();
        X500Name rootName = new X500Name("CN=Test Root CA,O=DSS service tests,C=PL");
        X509CertificateHolder root = certificate(rootName, rootName, BigInteger.ONE,
                rootKeys, rootKeys, true, now, provider);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificate(root);
        var extensions = new JcaX509ExtensionUtils();
        var crl = new X509v2CRLBuilder(rootName, Date.from(now.minus(5, ChronoUnit.MINUTES)));
        crl.setNextUpdate(Date.from(now.plus(1, ChronoUnit.DAYS)));
        crl.addExtension(Extension.authorityKeyIdentifier, false,
                extensions.createAuthorityKeyIdentifier(rootKeys.getPublic()));
        crl.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        generator.addCRL(crl.build(contentSigner(rootKeys.getPrivate(), provider)));

        Instant firstSigningTime = now.minus(2, ChronoUnit.MINUTES);
        Instant secondSigningTime = now.minus(1, ChronoUnit.MINUTES);
        addSigner(generator, rootName, rootKeys, "First signer", 101, firstSigningTime, now, provider);
        addSigner(generator, rootName, rootKeys, "Second signer", 102, secondSigningTime, now, provider);

        CMSSignedData signed = generator.generate(new CMSProcessableByteArray(
                "Document approved by two signers.".getBytes(StandardCharsets.UTF_8)), true);
        var rootCertificate = new JcaX509CertificateConverter().setProvider(provider).getCertificate(root);
        return new TwoSignatureDocument(signed, new CertificateToken(rootCertificate),
                Map.of("101", firstSigningTime, "102", secondSigningTime));
    }

    byte[] encoded() throws Exception {
        return signedData.getEncoded();
    }

    byte[] withTamperedContent() throws Exception {
        // Preserve both original SignerInfos, including their signed message-digest attributes.
        // Only the encapsulated content changes; it is deliberately not signed again.
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificates(signedData.getCertificates());
        generator.addCRLs(signedData.getCRLs());
        generator.addSigners(signedData.getSignerInfos());
        return generator.generate(new CMSProcessableByteArray(
                "Content changed after signing.".getBytes(StandardCharsets.UTF_8)), true).getEncoded();
    }

    private static void addSigner(CMSSignedDataGenerator generator, X500Name issuer, KeyPair issuerKeys,
                                  String name, long serial, Instant signingTime, Instant now,
                                  Provider provider) throws Exception {
        KeyPair keys = keyPair();
        X509CertificateHolder certificate = certificate(issuer,
                new X500Name("CN=" + name + ",O=DSS service tests,C=PL"), BigInteger.valueOf(serial),
                keys, issuerKeys, false, now, provider);
        generator.addCertificate(certificate);

        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(Date.from(signingTime)))));
        byte[] certificateDigest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                new DERSet(new SigningCertificateV2(new ESSCertIDv2(certificateDigest)))));
        var digestProvider = new JcaDigestCalculatorProviderBuilder().setProvider(provider).build();
        var signerBuilder = new JcaSignerInfoGeneratorBuilder(digestProvider)
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
        generator.addSignerInfoGenerator(signerBuilder.build(contentSigner(keys.getPrivate(), provider), certificate));
    }

    private static X509CertificateHolder certificate(X500Name issuer, X500Name subject, BigInteger serial,
                                                     KeyPair subjectKeys, KeyPair issuerKeys, boolean ca,
                                                     Instant now, Provider provider) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(issuer, serial,
                Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject, subjectKeys.getPublic());
        var extensions = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca
                ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                : KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extensions.createSubjectKeyIdentifier(subjectKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extensions.createAuthorityKeyIdentifier(issuerKeys.getPublic()));
        return builder.build(contentSigner(issuerKeys.getPrivate(), provider));
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        return generator.generateKeyPair();
    }

    private static ContentSigner contentSigner(PrivateKey key, Provider provider) throws Exception {
        return new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build(key);
    }
}
