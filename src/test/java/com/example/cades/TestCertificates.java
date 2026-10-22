package com.example.cades;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/** Certificates the test PKI does not issue on its own. */
final class TestCertificates {

    private static final AtomicLong SERIAL = new AtomicLong(5000);

    private TestCertificates() {
    }

    /**
     * A signer certificate with the QC statements a qualified CA writes:
     * QcCompliance, and QcSSCD when the key is on a QSCD.
     */
    static TestPki.CertificateAndKey qualifiedSigner(TestPki issuer, boolean qscd) throws Exception {
        List<ASN1Encodable> statements = new ArrayList<>();
        statements.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance));
        if (qscd) {
            statements.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD));
        }
        X509Certificate root = issuer.root().certificate();
        return signer(issuer, "CN=Qualified Signer, C=DE", root.getNotBefore(), root.getNotAfter(), statements);
    }

    /** A signer certificate that expired yesterday. */
    static TestPki.CertificateAndKey expiredSigner(TestPki issuer) throws Exception {
        Instant now = Instant.now();
        return signer(issuer, "CN=Expired Signer, C=DE", Date.from(now.minus(Duration.ofDays(30))),
                Date.from(now.minus(Duration.ofDays(1))), List.of());
    }

    private static TestPki.CertificateAndKey signer(TestPki issuer, String subject, Date notBefore,
                                                   Date notAfter, List<ASN1Encodable> qcStatements)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer.root().subject(), BigInteger.valueOf(SERIAL.incrementAndGet()),
                notBefore, notAfter, new X500Name(subject), keys.getPublic());
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation));
        if (!qcStatements.isEmpty()) {
            builder.addExtension(Extension.qCStatements, false,
                    new DERSequence(qcStatements.toArray(ASN1Encodable[]::new)));
        }

        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(TestPki.BC)
                .getCertificate(builder.build(TestPki.contentSigner(issuer.root().privateKey())));
        return new TestPki.CertificateAndKey(certificate, keys.getPrivate());
    }
}
