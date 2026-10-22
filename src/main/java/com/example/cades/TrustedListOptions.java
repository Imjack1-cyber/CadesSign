package com.example.cades;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;

/** Where the EU trusted lists come from and where they are cached. */
class TrustedListOptions {

    @Option(names = "--tl-cache", paramLabel = "<dir>",
            description = "trusted list cache (default: ~/.cache/cades/tl)")
    Path cache;

    @Option(names = "--lotl-url", paramLabel = "<url>",
            description = "List of Trusted Lists to start from (default: ${DEFAULT-VALUE})")
    String lotlUrl = TrustedLists.EU_LOTL_URL;

    @Option(names = "--lotl-oj-url", paramLabel = "<url>",
            description = "Official Journal publication announcing the LOTL signing "
                    + "certificates (default: the EU's); 'none' to rely on --lotl-keystore only")
    String officialJournalUrl = TrustedLists.EU_OJ_URL;

    @Option(names = "--lotl-keystore", paramLabel = "<file>",
            description = "certificates allowed to sign the LOTL, as PKCS#12 or PEM: the ones "
                    + "announced in the Official Journal (see docs/operations.md)")
    File lotlKeystore;

    @Option(names = "--lotl-keystore-password", arity = "0..1",
            fallbackValue = SecretResolver.PROMPT,
            description = "password of a PKCS#12 --lotl-keystore" + SecretResolver.FORMS)
    String lotlKeystorePassword;

    @Option(names = "--tl-max-age", paramLabel = "<days>",
            description = "refuse a cache older than this many days; 0 accepts any age "
                    + "(default: ${DEFAULT-VALUE})")
    int maxAgeDays = 14;

    TrustedLists trustedLists() {
        if (lotlKeystore == null) {
            throw new IllegalArgumentException("--lotl-keystore is required: the LOTL is "
                    + "trusted only when signed by a certificate announced in the Official "
                    + "Journal (see docs/operations.md)");
        }
        return new TrustedLists(
                cache != null ? cache : TrustedLists.defaultCacheDirectory(),
                lotlUrl,
                "none".equalsIgnoreCase(officialJournalUrl) ? null : officialJournalUrl,
                lotlSigners());
    }

    Duration maxAge() {
        return maxAgeDays <= 0 ? null : Duration.ofDays(maxAgeDays);
    }

    private CertificateSource lotlSigners() {
        if (!lotlKeystore.isFile()) {
            throw new IllegalArgumentException("LOTL keystore not found: " + lotlKeystore);
        }
        try {
            byte[] content = Files.readAllBytes(lotlKeystore.toPath());
            if (new String(content, 0, Math.min(content.length, 64), StandardCharsets.US_ASCII)
                    .contains("-----BEGIN")) {
                return pemCertificates();
            }
            char[] password = lotlKeystorePassword == null
                    ? new char[0]
                    : new SecretResolver().resolve("--lotl-keystore-password", lotlKeystorePassword);
            return new KeyStoreCertificateSource(lotlKeystore, "PKCS12", password);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to read the LOTL keystore " + lotlKeystore, e);
        }
    }

    private CertificateSource pemCertificates() throws Exception {
        CommonCertificateSource source = new CommonCertificateSource();
        try (InputStream in = Files.newInputStream(lotlKeystore.toPath())) {
            for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                source.addCertificate(new CertificateToken((X509Certificate) certificate));
            }
        }
        if (source.getNumberOfCertificates() == 0) {
            throw new IllegalArgumentException(lotlKeystore + " contains no certificates");
        }
        return source;
    }
}
