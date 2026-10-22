package com.example.cades;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Validates a detached CAdES signature and reports the level actually
 * achieved.
 *
 * <p>The verifier is deliberately starved: it is given the trust anchors and
 * <em>nothing else</em> — no CRL source, no OCSP source, no network AIA
 * fetcher. Any revocation data DSS uses must therefore have come from inside
 * the signature. That turns "is this really LT?" from a claim into a test:
 * a B-T signature dressed up as LT cannot pass, because the material needed
 * to validate it would be missing.
 */
public final class CAdESLtVerifier {

    private final List<X509Certificate> trustAnchors;

    public CAdESLtVerifier(X509Certificate trustAnchor) {
        this(List.of(trustAnchor));
    }

    public CAdESLtVerifier(List<X509Certificate> trustAnchors) {
        this.trustAnchors = List.copyOf(trustAnchors);
    }

    /**
     * Loads the trust anchor from a PKCS#12 keystore.
     *
     * <p>The {@code root} alias of the demo PKI is preferred; for any
     * other keystore the first self-signed certificate (i.e. the CA)
     * is used, falling back to the first certificate found.
     *
     * @param keystorePath path of the PKCS#12 keystore
     * @param password     keystore password; {@code null} for the
     *                     default demo password
     */
    public static CAdESLtVerifier fromKeystore(String keystorePath, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(keystorePath))) {
                ks.load(in, password);
            }

            X509Certificate root = (X509Certificate) ks.getCertificate("root");
            if (root == null) {
                root = firstSelfSigned(ks);
            }
            if (root == null) {
                root = firstCertificate(ks);
            }
            if (root == null) {
                throw new IllegalArgumentException(
                        "Keystore contains no certificate: " + keystorePath);
            }
            return new CAdESLtVerifier(root);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to load the trust anchor from " + keystorePath, e);
        }
    }

    /**
     * Creates a verifier that trusts every certificate in the system
     * default trust store (Java cacerts), so signatures rooted in public
     * CAs validate without a custom keystore.
     */
    public static CAdESLtVerifier fromSystemTrustStore() {
        Path path = Path.of(System.getProperty("java.home"), "lib", "security", "cacerts");
        if (!Files.exists(path)) {
            path = Path.of("/etc/ssl/certs/java/cacerts");
        }
        try {
            // cacerts is PKCS#12 or JKS depending on the JDK; the
            // "JKS" keystore type reads both.
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream in = Files.newInputStream(path)) {
                trustStore.load(in, "changeit".toCharArray());
            }
            List<X509Certificate> anchors = allCertificates(trustStore);
            if (anchors.isEmpty()) {
                throw new IllegalArgumentException(
                        "System trust store contains no certificates: " + path);
            }
            return new CAdESLtVerifier(anchors);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to load the system trust store from " + path, e);
        }
    }

    /**
     * Checks that the keystore opens, then ignores its certificates
     * and trusts the system trust store instead.
     *
     * @param keystorePath path of the PKCS#12 keystore
     * @param password     keystore password
     */
    public static CAdESLtVerifier fromKeystoreIgnoringTrustAnchors(String keystorePath, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(keystorePath))) {
                ks.load(in, password);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Unable to load keystore from " + keystorePath, e);
        }
        return fromSystemTrustStore();
    }

    private static List<X509Certificate> allCertificates(KeyStore ks) throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            if (ks.getCertificate(aliases.nextElement()) instanceof X509Certificate x509) {
                certificates.add(x509);
            }
        }
        return certificates;
    }

    private static X509Certificate firstSelfSigned(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            var certificate = ks.getCertificate(aliases.nextElement());
            if (certificate instanceof X509Certificate x509
                    && x509.getSubjectX500Principal().equals(x509.getIssuerX500Principal())) {
                return x509;
            }
        }
        return null;
    }

    private static X509Certificate firstCertificate(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            var certificate = ks.getCertificate(aliases.nextElement());
            if (certificate instanceof X509Certificate x509) {
                return x509;
            }
        }
        return null;
    }

    /**
     * @param signature      the detached CMS signature (.p7s)
     * @param signedContent  the original document the signature covers
     */
    public Result verify(DSSDocument signature, DSSDocument signedContent) {
        SignedDocumentValidator validator = validatorFor(signature);
        validator.setDetachedContents(List.of(signedContent));
        return validate(validator);
    }

    /**
     * Validates a self-contained (enveloped) signature.
     *
     * @param signature the CMS signature carrying the signed content
     */
    public Result verify(DSSDocument signature) {
        return validate(validatorFor(signature));
    }

    private SignedDocumentValidator validatorFor(DSSDocument signature) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signature);
        validator.setCertificateVerifier(offlineVerifier());
        return validator;
    }

    private Result validate(SignedDocumentValidator validator) {
        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();

        String signatureId = simpleReport.getFirstSignatureId();
        return new Result(
                simpleReport.getSignatureFormat(signatureId),
                simpleReport.getIndication(signatureId),
                reports);
    }

    private CommonCertificateVerifier offlineVerifier() {
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trustAnchors.forEach(anchor -> trusted.addCertificate(new CertificateToken(anchor)));

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setAIASource(null);
        return verifier;
    }

    /**
     * Outcome of a validation run.
     *
     * @param level      the signature level DSS determined, e.g. CAdES_BASELINE_LT
     * @param indication TOTAL_PASSED, INDETERMINATE or TOTAL_FAILED
     * @param reports    the full DSS reports, for detailed inspection
     */
    public record Result(SignatureLevel level, Indication indication, Reports reports) {

        public boolean isLongTerm() {
            return level == SignatureLevel.CAdES_BASELINE_LT
                    || level == SignatureLevel.CAdES_BASELINE_LTA;
        }

        public boolean isPassed() {
            return indication == Indication.TOTAL_PASSED;
        }

        /** The signature value verifies against the signer's key and the signed content is unchanged. */
        public boolean isSignatureIntact() {
            SignatureWrapper signature = signature();
            return signature != null && signature.isSignatureIntact() && signature.isSignatureValid();
        }

        /** The signer's certificate chain ends in one of the trust anchors. */
        public boolean isChainTrusted() {
            SignatureWrapper signature = signature();
            return signature != null
                    && signature.getCertificateChain().stream().anyMatch(CertificateWrapper::isTrusted);
        }

        /** At least one signature timestamp is present and cryptographically valid. */
        public boolean hasValidSignatureTimestamp() {
            return hasValidTimestamp(TimestampType.SIGNATURE_TIMESTAMP);
        }

        /** At least one archive timestamp is present and cryptographically valid. */
        public boolean hasValidArchiveTimestamp() {
            return hasValidTimestamp(TimestampType.ARCHIVE_TIMESTAMP);
        }

        /**
         * Whether the signature does what the requested level promises, judged by that level's
         * own content rather than always by B-LT. B and B-T carry no revocation data, so the
         * offline validation cannot conclude (INDETERMINATE) and is not held against them; they
         * pass on an intact signature, a trusted chain and, for B-T, a valid timestamp. B-LT and
         * B-LTA must validate completely from the embedded material.
         */
        public boolean isPassedFor(SignatureLevel requested) {
            if (level != requested) {
                return false;
            }
            return switch (requested) {
                case CAdES_BASELINE_B -> isSignatureIntact() && isChainTrusted();
                case CAdES_BASELINE_T -> isSignatureIntact() && isChainTrusted() && hasValidSignatureTimestamp();
                case CAdES_BASELINE_LT -> isPassed();
                case CAdES_BASELINE_LTA -> isPassed() && hasValidArchiveTimestamp();
                default -> isPassed();
            };
        }

        private SignatureWrapper signature() {
            String id = reports.getSimpleReport().getFirstSignatureId();
            return id == null ? null : reports.getDiagnosticData().getSignatureById(id);
        }

        private boolean hasValidTimestamp(TimestampType type) {
            String id = reports.getSimpleReport().getFirstSignatureId();
            return id != null && reports.getDiagnosticData().getTimestampList(id).stream()
                    .anyMatch(t -> t.getType() == type
                            && t.isSignatureValid() && t.isMessageImprintDataIntact());
        }
    }
}
