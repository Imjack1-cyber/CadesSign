package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * An RFC 3161 Time Stamp Authority that runs inside this JVM.
 *
 * <p>DSS talks to a TSA through {@link TSPSource}, which is a plain Java
 * interface — it does not mandate HTTP. So instead of starting a local TSA
 * server we satisfy the interface directly: DSS hands us a digest, we build a
 * genuine signed RFC 3161 token around it with BouncyCastle and hand the bytes
 * back. No sockets, no network, no ports to allocate in CI.
 *
 * <p>The tokens produced here are structurally real: they are CMS
 * SignedData over a TSTInfo, signed by a certificate carrying a critical
 * {@code id-kp-timeStamping} extended key usage. What they are not is
 * <em>trustworthy</em> — the time asserted is simply this machine's clock.
 *
 * <p>To move to production, delete this class and substitute DSS's
 * {@code OnlineTSPSource} pointed at a real TSA. Nothing else changes.
 */
public final class LocalTspSource implements TSPSource {

    private static final long serialVersionUID = 1L;

    /**
     * TSA policy OID. Under the ITU-T "example" arc (2.999) reserved by
     * RFC 5612 for documentation and testing, so it cannot collide with a
     * real policy.
     */
    private static final ASN1ObjectIdentifier DEMO_POLICY_OID =
            new ASN1ObjectIdentifier("2.999.1.2.3");

    private final TestPki.CertificateAndKey tsa;
    private final List<X509Certificate> chain;
    private final AtomicLong serialCounter = new AtomicLong(1L);
    private final AtomicReference<Instant> lastIssuedAt = new AtomicReference<>();

    /**
     * @param tsa    the timestamping certificate and its private key
     * @param issuer the CA certificate that issued {@code tsa}; included in
     *               the token so verifiers can build the chain
     */
    public LocalTspSource(TestPki.CertificateAndKey tsa, X509Certificate issuer) {
        this(tsa, List.of(tsa.certificate(), issuer));
    }

    /**
     * @param tsa   the timestamping certificate and its private key
     * @param chain the TSA certificate followed by its issuers; included in
     *              the token so verifiers can build the chain
     */
    public LocalTspSource(TestPki.CertificateAndKey tsa, List<X509Certificate> chain) {
        this.tsa = tsa;
        this.chain = List.copyOf(chain);
    }

    /**
     * Generation time of the most recent token. Revocation data must be
     * dated strictly after this instant for the signature to qualify as LT.
     */
    public Optional<Instant> lastIssuedAt() {
        return Optional.ofNullable(lastIssuedAt.get());
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest)
            throws DSSException {
        try {
            TimeStampRequest request = buildRequest(digestAlgorithm, digest);
            return new TimestampBinary(respondTo(request).getTimeStampToken().getEncoded());

        } catch (Exception e) {
            throw new DSSException(
                    "Local TSA failed to produce a timestamp token for digest algorithm "
                            + digestAlgorithm, e);
        }
    }

    /**
     * Answers a raw RFC 3161 request, for serving over HTTP.
     *
     * @param requestDer DER-encoded {@code TimeStampRequest}
     * @return DER-encoded {@code TimeStampResponse}
     */
    public byte[] processRequest(byte[] requestDer) throws DSSException {
        try {
            TimeStampRequest request = new TimeStampRequest(requestDer);
            return respondTo(request).getEncoded();
        } catch (Exception e) {
            throw new DSSException("Local TSA failed to process the timestamp request", e);
        }
    }

    private TimeStampRequest buildRequest(DigestAlgorithm digestAlgorithm, byte[] digest) {
        TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
        // Ask for the TSA certificate to be embedded; DSS needs it to
        // validate the timestamp and to collect its revocation data at LT.
        requestGenerator.setCertReq(true);
        return requestGenerator.generate(
                new ASN1ObjectIdentifier(digestAlgorithm.getOid()),
                digest,
                nextSerial());
    }

    private TimeStampResponse respondTo(TimeStampRequest request) throws Exception {
        DigestCalculatorProvider digestProvider =
                new JcaDigestCalculatorProviderBuilder().setProvider(TestPki.BC).build();

        // SHA-1 here is not a security choice: it is the ESSCertID hash that
        // RFC 3161 / RFC 5035 define for identifying the signing certificate.
        DigestCalculator certificateDigest =
                digestProvider.get(new AlgorithmIdentifier(TSPAlgorithms.SHA1));

        SignerInfoGenerator signerInfoGenerator =
                new JcaSignerInfoGeneratorBuilder(digestProvider)
                        .build(TestPki.contentSigner(tsa.privateKey()), tsa.certificate());

        TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(
                signerInfoGenerator, certificateDigest, DEMO_POLICY_OID);

        tokenGenerator.addCertificates(
                new JcaCertStore(chain));

        // Passed inline: TSPAlgorithms.ALLOWED is a raw Set, so a
        // parameterised local would only add an unchecked conversion.
        TimeStampResponseGenerator responseGenerator =
                new TimeStampResponseGenerator(tokenGenerator, TSPAlgorithms.ALLOWED);

        Instant generationTime = Instant.now();
        lastIssuedAt.set(generationTime);

        return responseGenerator.generate(request, nextSerial(), Date.from(generationTime));
    }

    private BigInteger nextSerial() {
        return BigInteger.valueOf(serialCounter.getAndIncrement());
    }
}
