package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
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

/**
 * Signs a document with keys from {@link SigningKeyOptions}. Without
 * further options the whole flow stays offline: in-process TSA plus
 * revocation material minted with the issuing CA's key. {@code --tsa-url}, {@code --ocsp-url} and {@code
 * --crl-url} substitute DSS's online sources.
 */
@picocli.CommandLine.Command(
        name = "sign",
        description = "Sign a document with CAdES Baseline LT. "
                + "Needs keys from --keystore, --signer (plus --tsa) or "
                + "--generate-keystore. Offline by default; --tsa-url "
                + "switches to an online TSA.")
class SignCommand implements Runnable {

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

    @picocli.CommandLine.Mixin
    KeystoreOptions keystore;

    @picocli.CommandLine.Mixin
    SigningKeyOptions keys;

    @Override
    public void run() {
        if (!input.isFile()) {
            throw new IllegalArgumentException("document not found: " + input);
        }

        SigningCredentials credentials = keys.resolve(keystore, tsaUrl != null);
        checkCredentialsReachLevel(credentials);

        CAdESLtSigner signer = new CAdESLtSigner(credentials, new SigningConfig(
                digest,
                level,
                packaging,
                tspSource(),
                null,
                crlSource(),
                ocspSource()));

        warnAboutOnlineTsaConstraint();

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
        if (level == SignatureLevel.CAdES_BASELINE_T || hasOnlineRevocation()) {
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
            return null;
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
            return null;
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

    /**
     * An online TSA chains to an external CA whose revocation data
     * the offline sources cannot provide, so the signature cannot
     * reach LT unless real revocation endpoints are supplied.
     */
    private void warnAboutOnlineTsaConstraint() {
        if (tsaUrl == null) {
            return;
        }
        if (!hasOnlineRevocation()) {
            System.out.println("Warning: --tsa-url without --ocsp-url/--crl-url "
                    + "can only reach B-T. The offline revocation sources cover "
                    + "the test PKI, not the external TSA's chain. Supply real "
                    + "revocation endpoints for both chains to reach LT.");
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
