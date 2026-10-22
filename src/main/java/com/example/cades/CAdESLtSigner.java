package com.example.cades;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Produces CAdES Baseline LT signatures (ETSI EN 319 122-1) over arbitrary
 * documents, including XML.
 *
 * <p><b>On signing XML with CAdES.</b> CAdES is CMS-based and signs opaque
 * octets, so it neither knows nor cares that the payload is XML. That is a
 * feature here: the XML is signed byte-for-byte, with no canonicalisation
 * step and therefore no XML-DSig canonicalisation pitfalls. The trade-off is
 * that the signature cannot live inside the XML document — hence DETACHED
 * packaging, which leaves the original file untouched and writes the
 * signature alongside it as a {@code .p7s}.
 *
 * <p><b>What "LT" adds.</b> Reaching B-LT requires three things beyond a
 * basic signature: a trusted timestamp over the signature (B-T), and then
 * the certificates and revocation data needed to validate it in future,
 * embedded into the signature itself. All three are enforced by DSS; if the
 * timestamp source or revocation data is unavailable, signing fails rather
 * than silently degrading to a lower level.
 */
public final class CAdESLtSigner {

    private final SigningCredentials credentials;
    private final SigningConfig config;

    public CAdESLtSigner(TestPki pki) {
        this(pki, SigningConfig.localDefaults());
    }

    public CAdESLtSigner(TestPki pki, DigestAlgorithm digestAlgorithm) {
        this(pki, new SigningConfig(
                digestAlgorithm,
                SignatureLevel.CAdES_BASELINE_LT,
                SignaturePackaging.DETACHED,
                null,
                null,
                null,
                null));
    }

    public CAdESLtSigner(TestPki pki, SigningConfig config) {
        this(pki.toCredentials(), config);
    }

    public CAdESLtSigner(SigningCredentials credentials, SigningConfig config) {
        this.credentials = credentials;
        this.config = config;
    }

    /**
     * Signs a document, producing a detached CAdES B-LT signature.
     *
     * @param document the content to sign; not modified
     * @return the DER-encoded CMS signature, suitable for writing as .p7s
     */
    public DSSDocument sign(DSSDocument document) {
        // Must stay per-invocation: hoisting these to fields lets one
        // document's timestamp time suppress the next document's freshness
        // wait, silently embedding stale revocation data.
        LocalTspSource localTsp = null;
        TSPSource tspSource = config.tspSource();
        if (tspSource == null && config.signatureLevel() != SignatureLevel.CAdES_BASELINE_B) {
            if (credentials.tsa() == null) {
                throw new IllegalStateException(
                        "no TSA key available: supply one or use an online TSA");
            }
            localTsp = new LocalTspSource(credentials.tsa(), credentials.tsaChain());
            tspSource = localTsp;
        }

        Supplier<Optional<Instant>> timestampTime = config.signatureTimestampTime();
        if (timestampTime == null) {
            // An in-process TSA knows its token's generation time, so the
            // revocation material can be dated strictly after it. An online
            // TSA does not expose it, so the wall clock stands in: waiting
            // for the next second boundary keeps the revocation material
            // strictly after the token, which is what LT requires.
            timestampTime = localTsp != null
                    ? localTsp::lastIssuedAt
                    : () -> Optional.of(Instant.now());
        }

        // Offline material answers for every certificate whose CA key is
        // at hand; online sources cover the rest, such as an external TSA.
        OfflineRevocation revocation =
                OfflineRevocation.forIssuers(credentials.issuers(), timestampTime);
        RevocationSource<CRL> crlSource =
                firstAnswer(revocation.crlSource(), config.crlSource());
        RevocationSource<OCSP> ocspSource =
                firstAnswer(revocation.ocspSource(), config.ocspSource());

        CAdESService service = newService(tspSource, crlSource, ocspSource);
        CAdESSignatureParameters parameters = newParameters();

        // Step 1 — DSS assembles the CMS SignedAttributes and returns the
        // exact octets that must be signed.
        ToBeSigned dataToSign = service.getDataToSign(document, parameters);

        // Step 2 — the private key operation: in memory for a file key, on
        // the device for a PKCS#11 smartcard or HSM. Nothing about the
        // surrounding flow changes.
        SignatureValue signatureValue =
                credentials.signer().sign(dataToSign, config.digestAlgorithm());

        // Step 3 — DSS embeds the signature value, then augments the result
        // up to LT: it timestamps the signature and embeds the collected
        // certificates and revocation data.
        return service.signDocument(document, parameters, signatureValue);
    }

    private static <T extends eu.europa.esig.dss.model.x509.revocation.Revocation>
            RevocationSource<T> firstAnswer(RevocationSource<T> primary,
                                            RevocationSource<T> fallback) {
        if (fallback == null) {
            return primary;
        }
        return (certificate, issuer) -> {
            var token = primary.getRevocationToken(certificate, issuer);
            return token != null ? token : fallback.getRevocationToken(certificate, issuer);
        };
    }

    private CAdESService newService(TSPSource tspSource,
                                    RevocationSource<CRL> crlSource,
                                    RevocationSource<OCSP> ocspSource) {
        CAdESService service = new CAdESService(newCertificateVerifier(crlSource, ocspSource));
        service.setTspSource(tspSource);
        return service;
    }

    /**
     * Builds a verifier wired to the configured sources.
     *
     * <p>The AIA source is cleared unless the config supplies one. A default
     * {@code CommonCertificateVerifier} installs a network-backed AIA
     * fetcher, which in an offline environment produces a confusing hang
     * followed by an unrelated-looking failure.
     */
    private CommonCertificateVerifier newCertificateVerifier(
            RevocationSource<CRL> crlSource, RevocationSource<OCSP> ocspSource) {
        CommonTrustedCertificateSource trustedCertificates = new CommonTrustedCertificateSource();
        credentials.trustAnchors().forEach(anchor ->
                trustedCertificates.addCertificate(new CertificateToken(anchor)));

        // Intermediates of either chain, e.g. a known online TSA chain,
        // since the AIA fetcher that would otherwise find them is disabled.
        CommonCertificateSource adjunctCertificates = new CommonCertificateSource();
        credentials.intermediates().forEach(certificate ->
                adjunctCertificates.addCertificate(new CertificateToken(certificate)));

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trustedCertificates);
        verifier.setAdjunctCertSources(adjunctCertificates);
        verifier.setCrlSource(crlSource);
        verifier.setOcspSource(ocspSource);
        verifier.setAIASource(config.aiaSource());

        // Left at the DSS default (ExceptionOnStatusAlert) on purpose: if
        // revocation data cannot be collected we want a loud failure, not a
        // signature that claims LT while lacking the material to prove it.
        return verifier;
    }

    private CAdESSignatureParameters newParameters() {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(config.signatureLevel());
        parameters.setSignaturePackaging(config.signaturePackaging());
        parameters.setDigestAlgorithm(config.digestAlgorithm());
        parameters.setSigningCertificate(new CertificateToken(credentials.signer().certificate()));
        parameters.setCertificateChain(credentials.signerChain().stream()
                .map(CertificateToken::new)
                .toList());
        return parameters;
    }

    /** Thrown when the private key operation fails. */
    public static final class SigningException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        SigningException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
