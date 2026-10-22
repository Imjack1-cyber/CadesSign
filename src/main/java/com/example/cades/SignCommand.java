package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.model.x509.extension.QcStatements;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;

/**
 * Signs a document with keys from {@link SigningKeyOptions}. Without
 * further options the whole flow stays offline: in-process TSA plus
 * revocation material minted with the issuing CA's key. {@code --tsa-url}, {@code --ocsp-url} and {@code
 * --crl-url} substitute DSS's online sources, {@code --online-revocation} follows the certificates'
 * own AIA and CRL distribution points, and {@code --strict} refuses every test-grade shortcut.
 */
@picocli.CommandLine.Command(
        name = "sign",
        description = "Sign a document with CAdES Baseline LT. "
                + "Needs keys from --keystore, --signer (plus --tsa), a "
                + "PKCS#11 token (--pkcs11-lib) or --generate-keystore. "
                + "Offline by default; --tsa-url switches to an online TSA.",
        exitCodeListHeading = "Exit codes:%n",
        exitCodeList = {
                "0:the signature reaches the requested level",
                "1:the signature was written but does not reach the requested level "
                        + "(with --strict it is deleted)",
                "2:invalid options or arguments",
                "3:keys, files or a network service could not be used"})
class SignCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "document to sign")
    File input;

    @Option(names = {"-o", "--output"},
            description = "file to write the signature to "
                    + "(default: <input>.p7s)")
    File output;

    @Option(names = "--tsa-url",
            description = "URL of an online RFC 3161 TSA "
                    + "(default: in-process TSA using the test PKI)")
    String tsaUrl;

    @Option(names = "--ocsp-url",
            description = "OCSP responder URL used instead of the "
                    + "certificate's AIA extension; repeatable")
    List<String> ocspUrls;

    @Option(names = "--crl-url",
            description = "CRL distribution point URL used instead of the "
                    + "certificate's CRL extension; repeatable")
    List<String> crlUrls;

    @Option(names = "--digest", converter = DigestConverter.class,
            description = "digest algorithm, e.g. SHA256, SHA384, SHA512 "
                    + "(default: ${DEFAULT-VALUE})")
    DigestAlgorithm digest = DigestAlgorithm.SHA256;

    @Option(names = "--level", converter = LevelConverter.class,
            description = "target signature level: B, B-T, LT, LTA "
                    + "(default: ${DEFAULT-VALUE})")
    SignatureLevel level = SignatureLevel.CAdES_BASELINE_LT;

    @Option(names = "--packaging", converter = PackagingConverter.class,
            description = "detached or enveloped (default: ${DEFAULT-VALUE})")
    SignaturePackaging packaging = SignaturePackaging.DETACHED;

    @Option(names = "--online-revocation",
            description = "fetch OCSP/CRL data and missing CA certificates from the "
                    + "URLs in the certificates themselves (AIA, CRL distribution points)")
    boolean onlineRevocation;

    @Option(names = "--strict",
            description = "production mode: refuse the in-process TSA, revocation data "
                    + "minted with a CA key, --generate-keystore and the default keystore "
                    + "password; implies --online-revocation; deletes the signature if it "
                    + "does not reach the requested level")
    boolean strict;

    @picocli.CommandLine.Mixin
    KeystoreOptions keystore;

    @picocli.CommandLine.Mixin
    SigningKeyOptions keys;

    @picocli.CommandLine.Mixin
    Pkcs11Options pkcs11;

    @Override
    public Integer call() {
        if (!input.isFile()) {
            throw new IllegalArgumentException("document not found: " + input);
        }
        if (strict) {
            checkStrict();
            onlineRevocation = true;
        }

        SigningCredentials credentials = keys.resolve(keystore, pkcs11, tsaUrl != null);
        try {
            return sign(strict ? credentials.withoutIssuers() : credentials);
        } finally {
            credentials.signer().close();
        }
    }

    private int sign(SigningCredentials credentials) {
        checkCredentialsReachLevel(credentials);
        describeQualification(credentials.signer());

        CAdESLtSigner signer = new CAdESLtSigner(credentials, new SigningConfig(
                digest,
                level,
                packaging,
                tspSource(),
                null,
                crlSource(),
                ocspSource(),
                aiaSource()));

        warnAboutOnlineTsaConstraint();
        noteTestOnlyMaterial(credentials);

        DSSDocument original = new FileDocument(input);
        DSSDocument signed = signer.sign(original);

        Path target = output == null
                ? Path.of(input.getPath() + ".p7s")
                : output.toPath();
        try (var out = Files.newOutputStream(target)) {
            signed.writeTo(out);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to write the signature to " + target, e);
        }
        System.out.println("Signature written to " + target);

        // Self-check against the roots that actually issued the signer
        // and TSA, not the --keystore trust setting, which may point elsewhere,
        // and against the requested level rather than always B-LT.
        CAdESLtVerifier verifier = new CAdESLtVerifier(credentials.trustAnchors());
        CAdESLtVerifier.Result result = packaging == SignaturePackaging.DETACHED
                ? verifier.verify(signed, original)
                : verifier.verify(signed);
        VerifyCommand.printSelfCheck(result, level);

        if (result.isPassedFor(level)) {
            return 0;
        }
        if (strict) {
            try {
                Files.deleteIfExists(target);
            } catch (Exception e) {
                System.err.println("Error: could not delete " + target + ": " + e.getMessage());
            }
            System.err.println("Error: the signature does not reach " + levelName()
                    + " and was deleted (--strict)");
        } else {
            System.err.println("Error: the signature does not reach " + levelName());
        }
        return 1;
    }

    /** The options --strict refuses outright, before any key is touched. */
    private void checkStrict() {
        if (keys.generateKeystore != null) {
            throw new IllegalArgumentException("--strict refuses --generate-keystore: "
                    + "a generated test PKI proves nothing to third parties");
        }
        if (level != SignatureLevel.CAdES_BASELINE_B && tsaUrl == null) {
            throw new IllegalArgumentException("--strict needs --tsa-url for level "
                    + levelName() + ": the in-process TSA is for testing only");
        }
        if (keystore.keystore != null && keystore.usesDefaultPassword()) {
            throw new IllegalArgumentException("--strict refuses the default keystore "
                    + "password: give --keystore-password");
        }
    }

    /**
     * Reports what the signing certificate says about itself in its QC
     * statements (ETSI EN 319 412-5). Whether the signature is really
     * qualified also depends on the EU trust lists, which verify
     * --trust-lotl checks.
     */
    private void describeQualification(SigningKey key) {
        QcStatements statements = CertificateExtensionsUtils.getQcStatements(
                new CertificateToken(key.certificate()));
        if (statements == null || !statements.isQcCompliance()) {
            return;
        }
        System.out.println("Qualified certificate: yes, key on a QSCD: "
                + (statements.isQcQSCD() ? "yes" : "no"));
        if (!strict) {
            return;
        }
        if (!statements.isQcQSCD()) {
            System.err.println("Warning: the qualified certificate does not declare a QSCD, "
                    + "so its signatures are advanced (AdES/QC), not qualified (QES).");
        }
        if (level == SignatureLevel.CAdES_BASELINE_B) {
            System.err.println("Warning: level B has no trusted timestamp; qualified "
                    + "signatures meant to last should use B-LT or B-LTA.");
        }
    }

    /** Says on stderr which parts of the signature come from test-only sources. */
    private void noteTestOnlyMaterial(SigningCredentials credentials) {
        if (keys.generateKeystore != null) {
            System.err.println("TEST-ONLY: signing with a freshly generated test PKI.");
        }
        if (level != SignatureLevel.CAdES_BASELINE_B && tsaUrl == null) {
            System.err.println("TEST-ONLY: the timestamp comes from the in-process TSA; "
                    + "use --tsa-url for a real timestamp authority.");
        }
        if (rank() >= 2 && !credentials.issuers().isEmpty()) {
            System.err.println("TEST-ONLY: revocation data may be minted with the CA key "
                    + "from the key file; use --strict to require the CA's real OCSP/CRL.");
        }
    }

    /** B = 0, B-T = 1, B-LT = 2, B-LTA = 3. */
    private int rank() {
        return switch (level) {
            case CAdES_BASELINE_T -> 1;
            case CAdES_BASELINE_LT -> 2;
            case CAdES_BASELINE_LTA -> 3;
            default -> 0;
        };
    }

    /**
     * Fails early, with a hint, when the keys cannot produce the
     * requested level instead of letting DSS abort mid-signature.
     */
    private void checkCredentialsReachLevel(SigningCredentials credentials) {
        if (level == SignatureLevel.CAdES_BASELINE_B) {
            return;
        }
        if (credentials.tsa() == null && tsaUrl == null) {
            throw new IllegalArgumentException("--level " + levelName() + " needs a "
                    + "timestamp: add --tsa <file> or --tsa-url <url>, or use --level B");
        }
        if (level == SignatureLevel.CAdES_BASELINE_T || hasOnlineRevocation() || onlineRevocation) {
            return;
        }
        List<java.security.cert.X509Certificate> uncovered =
                credentials.certificatesWithoutIssuerKey();
        if (!uncovered.isEmpty()) {
            throw new IllegalArgumentException("--level " + levelName() + " offline needs "
                    + "the issuing CA's private key for "
                    + uncovered.getFirst().getSubjectX500Principal().getName()
                    + ". Include the CA key in the --signer/--tsa file, supply "
                    + "--ocsp-url/--crl-url, or use --level B-T");
        }
    }

    private String levelName() {
        return level.name().replace("CAdES_BASELINE_", "").replace('_', '-');
    }

    private boolean hasOnlineRevocation() {
        return (ocspUrls != null && !ocspUrls.isEmpty())
                || (crlUrls != null && !crlUrls.isEmpty());
    }

    private eu.europa.esig.dss.spi.x509.tsp.TSPSource tspSource() {
        return tsaUrl == null ? null : new OnlineTSPSource(tsaUrl);
    }

    private RevocationSource<CRL> crlSource() {
        if (crlUrls == null || crlUrls.isEmpty()) {
            return onlineRevocation ? new OnlineCRLSource() : null;
        }
        return new OnlineCRLSource() {
            @Override
            public CRLToken getRevocationToken(
                    CertificateToken certificateToken,
                    CertificateToken issuerCertificateToken) {
                return getRevocationToken(
                        certificateToken, issuerCertificateToken, crlUrls);
            }
        };
    }

    private RevocationSource<OCSP> ocspSource() {
        if (ocspUrls == null || ocspUrls.isEmpty()) {
            return onlineRevocation ? new OnlineOCSPSource() : null;
        }
        return new OnlineOCSPSource() {
            @Override
            public OCSPToken getRevocationToken(
                    CertificateToken certificateToken,
                    CertificateToken issuerCertificateToken) {
                return getRevocationToken(
                        certificateToken, issuerCertificateToken, ocspUrls);
            }
        };
    }

    private AIASource aiaSource() {
        return onlineRevocation ? new DefaultAIASource(new CommonsDataLoader()) : null;
    }

    /**
     * An online TSA chains to an external CA whose revocation data
     * the offline sources cannot provide, so the signature cannot
     * reach LT unless real revocation endpoints are supplied.
     */
    private void warnAboutOnlineTsaConstraint() {
        if (tsaUrl == null) {
            return;
        }
        if (rank() >= 2 && !hasOnlineRevocation() && !onlineRevocation) {
            System.err.println("Warning: --tsa-url without --online-revocation or "
                    + "--ocsp-url/--crl-url can only reach B-T. The offline revocation "
                    + "sources cover the test PKI, not the external TSA's chain.");
        }
    }

    static final class DigestConverter implements ITypeConverter<DigestAlgorithm> {
        @Override
        public DigestAlgorithm convert(String value) {
            try {
                return DigestAlgorithm.valueOf(value.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "unknown digest algorithm: " + value
                                + " (expected SHA256, SHA384 or SHA512)");
            }
        }
    }

    static final class LevelConverter implements ITypeConverter<SignatureLevel> {
        @Override
        public SignatureLevel convert(String value) {
            String normalized = value.toUpperCase(Locale.ROOT).replace('-', '_');
            if (normalized.startsWith("CADES_")) {
                normalized = normalized.substring("CADES_".length());
            }
            if (normalized.startsWith("BASELINE_")) {
                normalized = normalized.substring("BASELINE_".length());
            }
            return switch (normalized) {
                case "B" -> SignatureLevel.CAdES_BASELINE_B;
                case "B_T", "T" -> SignatureLevel.CAdES_BASELINE_T;
                case "LT" -> SignatureLevel.CAdES_BASELINE_LT;
                case "LTA" -> SignatureLevel.CAdES_BASELINE_LTA;
                default -> throw new IllegalArgumentException(
                        "unknown signature level: " + value + " (expected B, B-T, LT or LTA)");
            };
        }
    }

    static final class PackagingConverter implements ITypeConverter<SignaturePackaging> {
        @Override
        public SignaturePackaging convert(String value) {
            return switch (value.toLowerCase(Locale.ROOT)) {
                case "detached" -> SignaturePackaging.DETACHED;
                // CMS terminology: the content is encapsulated
                // inside the signature ("enveloping"). The
                // opposite arrangement, a signature embedded in
                // the content, is what DSS calls ENVELOPED and
                // the CAdES service does not support.
                case "enveloped", "enveloping" -> SignaturePackaging.ENVELOPING;
                default -> throw new IllegalArgumentException(
                        "unknown packaging: " + value + " (expected detached or enveloping)");
            };
        }
    }
}
