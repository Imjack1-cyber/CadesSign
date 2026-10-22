package com.example.cades;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/**
 * Supplies revocation material offline so that DSS can reach B-LT.
 *
 * <p>This is the part of an LT demo that quietly goes wrong. B-LT means
 * "B-T plus the material needed to validate the signature later". If DSS
 * cannot collect revocation data for the chain it does not silently emit a
 * weaker signature — with the default {@code ExceptionOnStatusAlert} it
 * aborts with {@code "Revocation data is missing for one or more
 * certificate(s)."}
 *
 * <p><b>Why the material is minted lazily.</b> LT requires revocation data
 * that is <em>newer than the signature timestamp</em> — that is what proves
 * the certificate was still valid at the moment of signing. The timestamp is
 * created part-way through {@code signDocument}, so revocation data baked
 * before signing is always too old and DSS reports {@code "No revocation
 * data found after the best signature time"}. Responses are therefore
 * generated on demand: DSS asks during LT augmentation, which happens after
 * timestamping, and receives material stamped a moment later than the token.
 * This mirrors real deployments, where you sign, then fetch revocation data,
 * then augment.
 *
 * <p>Rather than hand-build DSS token objects, real DER-encoded CRLs and
 * OCSP responses are produced with BouncyCastle and parsed back through
 * DSS's {@code ExternalResources*Source}, exactly as if fetched from a
 * responder.
 */
public final class OfflineRevocation {

    private static final Duration VALIDITY = Duration.ofDays(1);

    private final List<TestPki.CertificateAndKey> issuers;
    private final Supplier<Optional<Instant>> signatureTimestampTime;
    private final AtomicLong crlNumber = new AtomicLong(1L);
    /** Serial number to revocation time, for tests of revoked signers. */
    private final Map<BigInteger, Instant> revoked = new ConcurrentHashMap<>();

    private OfflineRevocation(List<TestPki.CertificateAndKey> issuers,
                              Supplier<Optional<Instant>> signatureTimestampTime) {
        this.issuers = List.copyOf(issuers);
        this.signatureTimestampTime = signatureTimestampTime;
    }

    /**
     * @param pki                    the test PKI whose root acts as both CRL
     *                               issuer and OCSP responder
     * @param signatureTimestampTime supplies the time of the signature
     *                               timestamp, so revocation material can be
     *                               dated after it
     */
    public static OfflineRevocation forPki(
            TestPki pki, Supplier<Optional<Instant>> signatureTimestampTime) {
        return forIssuers(List.of(pki.root()), signatureTimestampTime);
    }

    /**
     * @param issuers                CA certificates and keys that act as CRL
     *                               issuer and OCSP responder for the
     *                               certificates they issued; certificates
     *                               of other CAs get no answer
     * @param signatureTimestampTime supplies the time of the signature
     *                               timestamp, so revocation material can be
     *                               dated after it
     */
    public static OfflineRevocation forIssuers(
            List<TestPki.CertificateAndKey> issuers,
            Supplier<Optional<Instant>> signatureTimestampTime) {
        return new OfflineRevocation(issuers, signatureTimestampTime);
    }

    /**
     * Timestamp of the revocation material.
     *
     * <p>DSS requires {@code thisUpdate} to fall strictly after the
     * signature timestamp, so a response minted in the same wall-clock
     * second as the token would still be rejected as stale — X.509 encodes
     * these times to one-second precision. Where a timestamp has already
     * been issued we therefore wait for the following second rather than
     * post-dating the response, which would leave a verifier holding
     * revocation data from the future.
     */
    private Instant revocationTime() {
        Optional<Instant> timestamp = signatureTimestampTime.get();
        if (timestamp.isEmpty()) {
            return Instant.now();
        }
        Instant mustBeAfter = timestamp.get().truncatedTo(ChronoUnit.SECONDS)
                .plusSeconds(1);
        awaitUntil(mustBeAfter);
        return Instant.now();
    }

    private static void awaitUntil(Instant deadline) {
        long waitMillis = Duration.between(Instant.now(), deadline).toMillis();
        if (waitMillis <= 0) {
            return;
        }
        try {
            Thread.sleep(waitMillis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** @return a CRL source that mints a current CRL on every request */
    public RevocationSource<CRL> crlSource() {
        return this::currentCrlToken;
    }

    /** @return an OCSP source that mints a current response on every request */
    public RevocationSource<OCSP> ocspSource() {
        return this::currentOcspToken;
    }

    /**
     * From now on, answers that {@code certificate} was revoked at
     * {@code when}: listed on the CRL, REVOKED over OCSP.
     */
    void revoke(X509Certificate certificate, Instant when) {
        revoked.put(certificate.getSerialNumber(), when);
    }

    /**
     * The current CRL of this certificate's issuer, DER-encoded, as a CRL
     * distribution point would serve it; empty if that CA's key is unknown.
     */
    Optional<byte[]> crlFor(X509Certificate certificate) {
        return SigningCredentials.findIssuer(certificate, issuers).map(issuer -> {
            try {
                return buildCrl(issuer);
            } catch (Exception e) {
                throw new RevocationGenerationException(
                        "Failed to generate a CRL for " + certificate.getSubjectX500Principal(), e);
            }
        });
    }

    /**
     * A GOOD OCSP response for this certificate, DER-encoded, as an OCSP
     * responder would serve it; empty if its issuer's key is unknown.
     */
    Optional<byte[]> ocspResponseFor(X509Certificate certificate) {
        return SigningCredentials.findIssuer(certificate, issuers).map(issuer -> {
            try {
                return buildGoodOcspResponse(certificate, issuer);
            } catch (Exception e) {
                throw new RevocationGenerationException("Failed to generate an OCSP response for "
                        + certificate.getSubjectX500Principal(), e);
            }
        });
    }

    private RevocationToken<CRL> currentCrlToken(
            CertificateToken certificate, CertificateToken certificateIssuer) {

        Optional<TestPki.CertificateAndKey> issuer = issuerOf(certificate);
        if (issuer.isEmpty()) {
            return null;
        }
        try {
            byte[] der = buildCrl(issuer.get());
            List<RevocationToken<CRL>> tokens =
                    new ExternalResourcesCRLSource(new ByteArrayInputStream(der))
                            .getRevocationTokens(certificate, certificateIssuer);
            return tokens.isEmpty() ? null : tokens.getFirst();

        } catch (Exception e) {
            throw new RevocationGenerationException(
                    "Failed to generate a CRL for " + certificate.getSubject(), e);
        }
    }

    private RevocationToken<OCSP> currentOcspToken(
            CertificateToken certificate, CertificateToken certificateIssuer) {

        Optional<TestPki.CertificateAndKey> issuer = issuerOf(certificate);
        if (issuer.isEmpty()) {
            return null;
        }
        try {
            byte[] der = buildGoodOcspResponse(certificate.getCertificate(), issuer.get());
            List<RevocationToken<OCSP>> tokens =
                    new ExternalResourcesOCSPSource(new ByteArrayInputStream(der))
                            .getRevocationTokens(certificate, certificateIssuer);
            return tokens.isEmpty() ? null : tokens.getFirst();

        } catch (Exception e) {
            throw new RevocationGenerationException(
                    "Failed to generate an OCSP response for " + certificate.getSubject(), e);
        }
    }

    /**
     * The CA that can answer for {@code certificate}. A trust anchor is
     * self-signed and its status is established by trust, not by
     * revocation, so it gets no answer; neither does a certificate whose
     * issuer's key is unknown.
     */
    private Optional<TestPki.CertificateAndKey> issuerOf(CertificateToken certificate) {
        X509Certificate x509 = certificate.getCertificate();
        if (SigningCredentials.isSelfSigned(x509)) {
            return Optional.empty();
        }
        return SigningCredentials.findIssuer(x509, issuers);
    }

    /**
     * A CRL listing the revoked certificates, normally none. In X.509 a
     * certificate is asserted GOOD by its <em>absence</em> from the
     * issuer's CRL, so an empty list is precisely what "nothing has been
     * revoked" looks like.
     */
    private byte[] buildCrl(TestPki.CertificateAndKey issuer) throws Exception {
        Instant issuedAt = revocationTime();
        Date thisUpdate = Date.from(issuedAt);
        Date nextUpdate = Date.from(issuedAt.plus(VALIDITY));

        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer.subject(), thisUpdate);
        builder.setNextUpdate(nextUpdate);
        builder.addExtension(Extension.cRLNumber, false,
                new CRLNumber(BigInteger.valueOf(crlNumber.getAndIncrement())));
        revoked.forEach((serial, when) ->
                builder.addCRLEntry(serial, Date.from(when), CRLReason.keyCompromise));

        return builder.build(TestPki.contentSigner(issuer.privateKey())).getEncoded();
    }

    /**
     * A signed OCSP response for one certificate: GOOD unless it was revoked.
     *
     * <p>The CA signs the response itself, so the responder identity is the
     * issuing CA. That avoids needing a delegated responder certificate
     * bearing {@code id-kp-OCSPSigning}.
     */
    private byte[] buildGoodOcspResponse(X509Certificate subject,
                                         TestPki.CertificateAndKey issuer) throws Exception {
        DigestCalculatorProvider digestProvider =
                new JcaDigestCalculatorProviderBuilder().setProvider(TestPki.BC).build();
        DigestCalculator sha1 = digestProvider.get(CertificateID.HASH_SHA1);

        CertificateID certificateId = new JcaCertificateID(
                sha1, issuer.certificate(), subject.getSerialNumber());

        Instant issuedAt = revocationTime();
        Date thisUpdate = Date.from(issuedAt);
        Date nextUpdate = Date.from(issuedAt.plus(VALIDITY));

        BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(issuer.publicKey(), sha1);
        Instant revokedAt = revoked.get(subject.getSerialNumber());
        CertificateStatus status = revokedAt == null
                ? CertificateStatus.GOOD
                : new RevokedStatus(Date.from(revokedAt), CRLReason.keyCompromise);
        builder.addResponse(certificateId, status, thisUpdate, nextUpdate);

        X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer.certificate());
        BasicOCSPResp basicResponse = builder.build(
                TestPki.contentSigner(issuer.privateKey()),
                new X509CertificateHolder[]{issuerHolder},
                Date.from(issuedAt));

        return new OCSPRespBuilder()
                .build(OCSPRespBuilder.SUCCESSFUL, basicResponse)
                .getEncoded();
    }

    /** Thrown when offline revocation material cannot be produced. */
    public static final class RevocationGenerationException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        RevocationGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
