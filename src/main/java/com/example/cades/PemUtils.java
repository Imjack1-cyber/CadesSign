package com.example.cades;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for loading certificates and private keys from PEM files.
 */
public final class PemUtils {

    private static final String BC = TestPki.BC;

    // TestPki.BC is a compile-time constant, so referencing it does not
    // run TestPki's static initialiser; register the provider here too.
    static {
        if (Security.getProvider(TestPki.BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PemUtils() {}

    /**
     * Loads all X.509 certificates from a PEM file.
     *
     * @param pemFile the PEM file to read
     * @return list of certificates (empty if none found)
     * @throws IOException if the file cannot be read or contains invalid PEM
     */
    public static List<X509Certificate> loadCertificates(File pemFile) throws IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC);
        try (FileReader reader = new FileReader(pemFile);
             PEMParser parser = new PEMParser(reader)) {
            Object obj;
            while ((obj = parser.readObject()) != null) {
                if (obj instanceof X509Certificate cert) {
                    certificates.add(cert);
                } else if (obj instanceof X509CertificateHolder holder) {
                    try {
                        certificates.add(converter.getCertificate(holder));
                    } catch (Exception e) {
                        throw new IOException("Failed to convert X509CertificateHolder", e);
                    }
                }
            }
        }
        return certificates;
    }

    /**
     * Loads a private key from a PEM file. The PEM may contain an encrypted
     * private key (PKCS#8 or PKCS#1), which will be decrypted using the
     * provided password.
     *
     * @param pemFile the PEM file to read
     * @param password password for decrypting an encrypted private key, or
     *                 {@code null} if the key is not encrypted
     * @return the private key, or {@code null} if no private key is found
     * @throws IOException if the file cannot be read or contains invalid PEM
     */
    public static PrivateKey loadPrivateKey(File pemFile, char[] password) throws IOException {
        List<PrivateKey> keys = loadPrivateKeys(pemFile, password);
        return keys.isEmpty() ? null : keys.getFirst();
    }

    /**
     * Loads every private key from a PEM file, whether stored as
     * PKCS#1 ({@code BEGIN RSA PRIVATE KEY}), PKCS#8 ({@code BEGIN
     * PRIVATE KEY}) or encrypted PKCS#8 ({@code BEGIN ENCRYPTED PRIVATE
     * KEY}).
     *
     * @param pemFile  the PEM file to read
     * @param password password for decrypting encrypted keys, or
     *                 {@code null} if the keys are not encrypted
     * @return the private keys in file order (empty if none found)
     * @throws IOException if the file cannot be read or contains invalid PEM
     */
    public static List<PrivateKey> loadPrivateKeys(File pemFile, char[] password)
            throws IOException {
        List<PrivateKey> keys = new ArrayList<>();
        try (FileReader reader = new FileReader(pemFile);
             PEMParser parser = new PEMParser(reader)) {
            Object obj;
            while ((obj = parser.readObject()) != null) {
                PrivateKey key = toPrivateKey(obj, password);
                if (key != null) {
                    keys.add(key);
                }
            }
        }
        return keys;
    }

    private static PrivateKey toPrivateKey(Object obj, char[] password) {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC);
        try {
            if (obj instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (obj instanceof PEMEncryptedKeyPair encrypted) {
                if (password == null) {
                    throw new IllegalArgumentException(
                            "PEM private key is encrypted but no password was provided");
                }
                PEMDecryptorProvider decryptor =
                        new JcePEMDecryptorProviderBuilder().setProvider(BC).build(password);
                PEMKeyPair keyPair = encrypted.decryptKeyPair(decryptor);
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (obj instanceof PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                if (password == null) {
                    throw new IllegalArgumentException(
                            "PEM private key is encrypted but no password was provided");
                }
                PrivateKeyInfo info = encrypted.decryptPrivateKeyInfo(
                        new JceOpenSSLPKCS8DecryptorProviderBuilder()
                                .setProvider(BC).build(password));
                return converter.getPrivateKey(info);
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Failed to read the PEM private key (wrong password?)", e);
        }
        return null;
    }
}