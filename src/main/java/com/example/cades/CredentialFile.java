package com.example.cades;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads one party's key material (the signer or the TSA) from a
 * PKCS#12/PFX keystore or a PEM file.
 *
 * <p>The format is detected from the content, not the file name, since
 * uploaded files often have no extension. Besides the party's own key
 * and chain, the file may hold CA keys; those are returned as issuers so
 * offline revocation data can be minted for the chain.
 *
 * <p>A file may also hold certificates only, as published for an online
 * TSA such as FreeTSA. {@link #entry} is then {@code null} and
 * {@link #chain} starts at the end-entity certificate.
 *
 * @param entry   the party's certificate and private key; {@code null}
 *                when the file holds no private key
 * @param chain   the party's certificate first, then its issuers
 * @param issuers CA certificates in the file whose key is also present
 */
public record CredentialFile(
        TestPki.CertificateAndKey entry,
        List<X509Certificate> chain,
        List<TestPki.CertificateAndKey> issuers) {

    private static final String PEM_MARKER = "-----BEGIN";

    // TestPki.BC is a compile-time constant, so referencing it does not
    // run TestPki's static initialiser; register the provider here too.
    static {
        if (Security.getProvider(TestPki.BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * @param file           PKCS#12/PFX or PEM file
     * @param password       keystore password, or the password of an
     *                       encrypted PEM key; may be {@code null} for an
     *                       unencrypted PEM
     * @param preferredAlias PKCS#12 alias to use when the keystore holds
     *                       several end-entity keys, e.g. {@code signer}
     */
    public static CredentialFile load(File file, char[] password, String preferredAlias) {
        if (!file.isFile()) {
            throw new IllegalArgumentException("credential file not found: " + file);
        }
        byte[] content;
        try {
            content = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            throw new IllegalArgumentException("Unable to read " + file, e);
        }
        List<TestPki.CertificateAndKey> pairs;
        List<X509Certificate> certificates;
        // ISO-8859-1 maps every byte to one char, so binary PKCS#12 decodes safely.
        if (new String(content, StandardCharsets.ISO_8859_1).contains(PEM_MARKER)) {
            certificates = readPemCertificates(file);
            pairs = pairKeys(readPemKeys(file, password), certificates, file);
        } else {
            KeyStore keyStore = readPkcs12(content, password, file);
            certificates = new ArrayList<>();
            pairs = new ArrayList<>();
            readPkcs12Entries(keyStore, password, preferredAlias, certificates, pairs, file);
        }

        if (pairs.isEmpty()) {
            if (certificates.isEmpty()) {
                throw new IllegalArgumentException(
                        file + " contains neither a private key nor a certificate");
            }
            return new CredentialFile(null,
                    SigningCredentials.buildChain(endEntity(certificates), certificates),
                    List.of());
        }

        TestPki.CertificateAndKey entry = chooseEntry(pairs);
        List<TestPki.CertificateAndKey> issuers = pairs.stream()
                .filter(pair -> pair != entry)
                .filter(pair -> pair.certificate().getBasicConstraints() != -1
                        || SigningCredentials.isSelfSigned(pair.certificate()))
                .toList();
        List<X509Certificate> pool = new ArrayList<>(certificates);
        issuers.forEach(issuer -> pool.add(issuer.certificate()));
        return new CredentialFile(entry,
                SigningCredentials.buildChain(entry.certificate(), pool), issuers);
    }

    private static List<X509Certificate> readPemCertificates(File file) {
        try {
            return PemUtils.loadCertificates(file);
        } catch (Exception e) {
            throw damaged("certificates", file, e);
        }
    }

    private static List<PrivateKey> readPemKeys(File file, char[] password) {
        try {
            return PemUtils.loadPrivateKeys(file, password);
        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("no password")) {
                throw e;
            }
            throw damaged("private keys", file, e);
        } catch (Exception e) {
            throw damaged("private keys", file, e);
        }
    }

    /**
     * The CLI prints only the message, so it names the likely cause: PEM
     * blocks broken by copy-paste (lost or extra base64 characters).
     */
    private static IllegalArgumentException damaged(String what, File file, Exception cause) {
        return new IllegalArgumentException("Unable to read " + what + " from " + file
                + ": the PEM data is damaged, truncated or encrypted with another "
                + "password. Re-export or re-download the file instead of copying "
                + "it by hand (" + rootMessage(cause) + ")", cause);
    }

    private static String rootMessage(Throwable error) {
        Throwable root = error;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root.getMessage() != null ? root.getMessage() : root.getClass().getSimpleName();
    }

    /** The certificate that issues no other certificate in the file. */
    private static X509Certificate endEntity(List<X509Certificate> certificates) {
        return certificates.stream()
                .filter(candidate -> certificates.stream().noneMatch(other ->
                        other != candidate && SigningCredentials.isIssuedBy(other, candidate)))
                .findFirst()
                .orElse(certificates.getFirst());
    }

    private static KeyStore readPkcs12(byte[] content, char[] password, File file) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new ByteArrayInputStream(content), password);
            return keyStore;
        } catch (Exception e) {
            throw new IllegalArgumentException(file + " is neither a PEM file nor a "
                    + "PKCS#12 keystore that opens with the given password", e);
        }
    }

    private static void readPkcs12Entries(KeyStore keyStore, char[] password,
                                          String preferredAlias,
                                          List<X509Certificate> certificates,
                                          List<TestPki.CertificateAndKey> pairs,
                                          File file) {
        try {
            for (String alias : Collections.list(keyStore.aliases())) {
                Certificate[] chain = keyStore.getCertificateChain(alias);
                if (chain != null) {
                    for (Certificate certificate : chain) {
                        if (certificate instanceof X509Certificate x509) {
                            certificates.add(x509);
                        }
                    }
                } else if (keyStore.getCertificate(alias) instanceof X509Certificate x509) {
                    certificates.add(x509);
                }
                if (keyStore.isKeyEntry(alias)
                        && keyStore.getKey(alias, password) instanceof PrivateKey key
                        && keyStore.getCertificate(alias) instanceof X509Certificate x509) {
                    TestPki.CertificateAndKey pair = new TestPki.CertificateAndKey(x509, key);
                    // The preferred alias goes first so chooseEntry picks it.
                    if (alias.equalsIgnoreCase(preferredAlias)) {
                        pairs.addFirst(pair);
                    } else {
                        pairs.add(pair);
                    }
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to read the entries of " + file, e);
        }
    }

    private static List<TestPki.CertificateAndKey> pairKeys(
            List<PrivateKey> keys, List<X509Certificate> certificates, File file) {
        List<TestPki.CertificateAndKey> pairs = new ArrayList<>();
        for (PrivateKey key : keys) {
            X509Certificate match = certificates.stream()
                    .filter(certificate -> belongsTo(key, certificate))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            file + " holds a private key without a matching certificate"));
            pairs.add(new TestPki.CertificateAndKey(match, key));
        }
        return pairs;
    }

    /**
     * Picks the party's own entry: the first end-entity key, or the only
     * key when the file holds nothing else.
     */
    private static TestPki.CertificateAndKey chooseEntry(List<TestPki.CertificateAndKey> pairs) {
        return pairs.stream()
                .filter(pair -> pair.certificate().getBasicConstraints() == -1)
                .findFirst()
                .orElse(pairs.getFirst());
    }

    /** Proves key ownership by signing a challenge and verifying it. */
    private static boolean belongsTo(PrivateKey key, X509Certificate certificate) {
        // No shortcut on getAlgorithm(): providers disagree on names
        // ("EC" vs "ECDSA"), and a mismatched key type fails below anyway.
        try {
            String algorithm = TestPki.signatureAlgorithmFor(key);
            byte[] challenge = "cades-lt key match".getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance(algorithm, TestPki.BC);
            signer.initSign(key);
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(algorithm, TestPki.BC);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
