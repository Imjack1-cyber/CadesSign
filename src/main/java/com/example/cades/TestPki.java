package com.example.cades;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Generates or loads a persistent offline test PKI for the CAdES B-LT demo using a PKCS12 keystore.
 */
public final class TestPki {

    static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;

    private static final String KEYSTORE_FILE = "test-pki.p12";
    private static final char[] KEYSTORE_PASSWORD = "passwort".toCharArray();

    private static final String CRL_URL = "http://offline.invalid/demo.crl";
    private static final String OCSP_URL = "http://offline.invalid/ocsp";

    static {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final CertificateAndKey root;
    private final CertificateAndKey signer;
    private final CertificateAndKey tsa;

    private TestPki(CertificateAndKey root, CertificateAndKey signer, CertificateAndKey tsa) {
        this.root = root;
        this.signer = signer;
        this.tsa = tsa;
    }

    public record CertificateAndKey(X509Certificate certificate, PrivateKey privateKey)
            implements Serializable {

        public PublicKey publicKey() {
            return certificate.getPublicKey();
        }

        public X500Name subject() {
            return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        }
    }

    public CertificateAndKey root() {
        return root;
    }

    public CertificateAndKey signer() {
        return signer;
    }

    public CertificateAndKey tsa() {
        return tsa;
    }

    /**
     * Lädt die Test-PKI aus dem Keystore, falls dieser existiert.
     * Andernfalls wird eine neue generiert und im Keystore gespeichert.
     */
    public static TestPki generate() {
        return generate(KEYSTORE_FILE, null);
    }

    /**
     * Lädt die Test-PKI aus einem beliebigen Keystore, falls dieser
     * existiert. Andernfalls wird eine neue generiert und dort gespeichert.
     * Ein vorhandener Keystore, der sich nicht laden lässt (falsches
     * Passwort, fehlende Aliase), wird nie überschrieben.
     *
     * @param keystorePath path of the PKCS#12 keystore
     * @param password     keystore password; {@code null} falls back to the
     *                     default demo password
     */
    public static TestPki generate(String keystorePath, char[] password) {
        return new File(keystorePath).exists()
                ? load(keystorePath, password)
                : create(keystorePath, password);
    }

    /**
     * Lädt die Test-PKI aus einem vorhandenen Keystore. Fehlt die Datei,
     * wird nichts erzeugt.
     *
     * @param keystorePath path of the PKCS#12 keystore
     * @param password     keystore password; {@code null} falls back to the
     *                     default demo password
     */
    public static TestPki load(String keystorePath, char[] password) {
        char[] effectivePassword = password != null ? password : KEYSTORE_PASSWORD;
        File file = new File(keystorePath);
        if (!file.isFile()) {
            throw new PkiGenerationException("keystore not found: " + keystorePath, null);
        }
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(file)) {
                ks.load(fis, effectivePassword);
            }

            CertificateAndKey rootEntry = loadEntry(ks, "root", effectivePassword);
            CertificateAndKey signerEntry = loadEntry(ks, "signer", effectivePassword);
            CertificateAndKey tsaEntry = loadEntry(ks, "tsa", effectivePassword);

            return new TestPki(rootEntry, signerEntry, tsaEntry);
        } catch (Exception e) {
            throw new PkiGenerationException("Unable to load the test PKI from "
                    + keystorePath + " (wrong password, or the keystore lacks the "
                    + "root/signer/tsa entries)", e);
        }
    }

    /**
     * Erzeugt eine neue Test-PKI und speichert sie im Keystore. Eine
     * vorhandene Datei wird nie überschrieben.
     *
     * @param keystorePath path of the PKCS#12 keystore to create
     * @param password     keystore password; {@code null} falls back to the
     *                     default demo password
     */
    public static TestPki create(String keystorePath, char[] password) {
        return create(keystorePath, password, CRL_URL, OCSP_URL);
    }

    /**
     * Like {@link #create(String, char[])}, with the CRL distribution point
     * and OCSP responder URLs written into the signer and TSA certificates,
     * so tests can serve real revocation data for them.
     */
    static TestPki create(String keystorePath, char[] password, String crlUrl, String ocspUrl) {
        return create(keystorePath, password, crlUrl, ocspUrl, "RSA");
    }

    /**
     * Like {@link #create(String, char[], String, String)}, with every key
     * of the given algorithm: {@code RSA} (2048 bit) or {@code EC} (P-256).
     */
    static TestPki create(String keystorePath, char[] password, String crlUrl, String ocspUrl,
                          String keyAlgorithm) {
        char[] effectivePassword = password != null ? password : KEYSTORE_PASSWORD;
        File file = new File(keystorePath);
        if (file.exists()) {
            throw new PkiGenerationException("refusing to overwrite existing file: "
                    + keystorePath, null);
        }

        try {
            Instant now = Instant.now();
            Date notBefore = Date.from(now.minus(Duration.ofHours(1)));
            Date notAfter = Date.from(now.plus(Duration.ofDays(365)));

            KeyPair rootKeys = generateKeyPair(keyAlgorithm);
            X509Certificate rootCert = buildRootCa(rootKeys, notBefore, notAfter);
            CertificateAndKey rootEntry = new CertificateAndKey(rootCert, rootKeys.getPrivate());

            KeyPair signerKeys = generateKeyPair(keyAlgorithm);
            X509Certificate signerCert = buildSigningCertificate(
                    signerKeys.getPublic(), rootEntry, notBefore, notAfter, crlUrl, ocspUrl);

            KeyPair tsaKeys = generateKeyPair(keyAlgorithm);
            X509Certificate tsaCert = buildTsaCertificate(
                    tsaKeys.getPublic(), rootEntry, notBefore, notAfter, crlUrl);

            TestPki pki = new TestPki(
                    rootEntry,
                    new CertificateAndKey(signerCert, signerKeys.getPrivate()),
                    new CertificateAndKey(tsaCert, tsaKeys.getPrivate()));

            // In PKCS12 Keystore abspeichern
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            saveEntry(ks, "root", pki.root(), effectivePassword);
            saveEntry(ks, "signer", pki.signer(), effectivePassword);
            saveEntry(ks, "tsa", pki.tsa(), effectivePassword);

            try (FileOutputStream fos = new FileOutputStream(file)) {
                ks.store(fos, effectivePassword);
            }

            return pki;

        } catch (Exception e) {
            throw new PkiGenerationException("Failed to generate or save the offline test PKI", e);
        }
    }

    /** The signer and TSA of this PKI, both issued by its root. */
    public SigningCredentials toCredentials() {
        return new SigningCredentials(
                SigningKey.software(signer), List.of(signer.certificate(), root.certificate()),
                tsa, List.of(tsa.certificate(), root.certificate()),
                List.of(root));
    }

    private static CertificateAndKey loadEntry(KeyStore ks, String alias, char[] password) throws Exception {
        PrivateKey key = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (key == null || cert == null) {
            throw new IllegalStateException("keystore has no key entry '" + alias + "'");
        }
        return new CertificateAndKey(cert, key);
    }

    private static void saveEntry(KeyStore ks, String alias, CertificateAndKey entry, char[] password) throws Exception {
        ks.setKeyEntry(alias, entry.privateKey(), password, new java.security.cert.Certificate[]{entry.certificate()});
    }

    private static KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, BC);
        if ("EC".equals(algorithm)) {
            generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        } else {
            generator.initialize(KEY_SIZE);
        }
        return generator.generateKeyPair();
    }

    private static X509Certificate buildRootCa(KeyPair keys, Date notBefore, Date notAfter)
            throws Exception {

        X500Name subject = new X500Name("CN=CAdES Demo Root CA, O=Example, C=DE");
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, keys.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                utils.createSubjectKeyIdentifier(keys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                utils.createAuthorityKeyIdentifier(keys.getPublic()));

        return toCertificate(builder.build(contentSigner(keys.getPrivate())));
    }

    private static X509Certificate buildSigningCertificate(
            PublicKey subjectKey, CertificateAndKey issuer, Date notBefore, Date notAfter,
            String crlUrl, String ocspUrl) throws Exception {

        X500Name subject = new X500Name("CN=CAdES Demo Signer, O=Example, C=DE");
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer.subject(), BigInteger.valueOf(1001L),
                notBefore, notAfter, subject, subjectKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                utils.createSubjectKeyIdentifier(subjectKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                utils.createAuthorityKeyIdentifier(issuer.publicKey()));
        builder.addExtension(Extension.cRLDistributionPoints, false, crlDistributionPoints(crlUrl));
        builder.addExtension(Extension.authorityInfoAccess, false, authorityInfoAccess(ocspUrl));

        return toCertificate(builder.build(contentSigner(issuer.privateKey())));
    }

    private static X509Certificate buildTsaCertificate(
            PublicKey subjectKey, CertificateAndKey issuer, Date notBefore, Date notAfter,
            String crlUrl) throws Exception {

        X500Name subject = new X500Name("CN=CAdES Demo TSA, O=Example, C=DE");
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer.subject(), BigInteger.valueOf(2001L),
                notBefore, notAfter, subject, subjectKey);

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                utils.createSubjectKeyIdentifier(subjectKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                utils.createAuthorityKeyIdentifier(issuer.publicKey()));
        builder.addExtension(Extension.cRLDistributionPoints, false, crlDistributionPoints(crlUrl));

        return toCertificate(builder.build(contentSigner(issuer.privateKey())));
    }

    private static CRLDistPoint crlDistributionPoints(String crlUrl) {
        GeneralName uri = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName name = new DistributionPointName(new GeneralNames(uri));
        return new CRLDistPoint(
                new DistributionPoint[]{new DistributionPoint(name, null, null)});
    }

    private static AuthorityInformationAccess authorityInfoAccess(String ocspUrl) {
        GeneralName uri = new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl);
        return new AuthorityInformationAccess(
                new AccessDescription(AccessDescription.id_ad_ocsp, uri));
    }

    static ContentSigner contentSigner(PrivateKey key) throws OperatorCreationException {
        return new JcaContentSignerBuilder(signatureAlgorithmFor(key)).setProvider(BC).build(key);
    }

    /** SHA-256 signature algorithm matching the key type of {@code key}. */
    static String signatureAlgorithmFor(PrivateKey key) {
        return switch (key.getAlgorithm().toUpperCase(java.util.Locale.ROOT)) {
            case "RSA" -> SIGNATURE_ALGORITHM;
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "ED25519" -> "Ed25519";
            case "ED448" -> "Ed448";
            case "DSA" -> "SHA256withDSA";
            default -> throw new IllegalArgumentException(
                    "unsupported key algorithm: " + key.getAlgorithm());
        };
    }

    private static X509Certificate toCertificate(X509CertificateHolder holder) throws Exception {
        return new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    }

    public static final class PkiGenerationException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        PkiGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}