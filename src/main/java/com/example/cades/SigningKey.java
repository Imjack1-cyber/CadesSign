package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;

import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 * The signer's certificate and the operation that signs with its private
 * key. The key may be a file key in memory or live on a smartcard or HSM
 * that never lets it out; the signing flow is the same for both.
 */
public interface SigningKey extends AutoCloseable {

    /** The signer's certificate. */
    X509Certificate certificate();

    /** The key's algorithm family, e.g. RSA or ECDSA. */
    EncryptionAlgorithm encryptionAlgorithm();

    /**
     * Signs the octets DSS prepared.
     *
     * @param data   the DER-encoded signed attributes
     * @param digest the digest algorithm of the signature
     */
    SignatureValue sign(ToBeSigned data, DigestAlgorithm digest);

    /** Releases the token session, if any. */
    @Override
    default void close() {
    }

    /** A private key held in memory, e.g. read from a PKCS#12 or PEM file. */
    static SigningKey software(TestPki.CertificateAndKey entry) {
        return new SigningKey() {
            @Override
            public X509Certificate certificate() {
                return entry.certificate();
            }

            @Override
            public EncryptionAlgorithm encryptionAlgorithm() {
                return EncryptionAlgorithm.forKey(entry.privateKey());
            }

            @Override
            public SignatureValue sign(ToBeSigned data, DigestAlgorithm digest) {
                SignatureAlgorithm algorithm =
                        SignatureAlgorithm.getAlgorithm(encryptionAlgorithm(), digest);
                try {
                    Signature signature = Signature.getInstance(algorithm.getJCEId(), TestPki.BC);
                    signature.initSign(entry.privateKey());
                    signature.update(data.getBytes());
                    return new SignatureValue(algorithm, signature.sign());
                } catch (Exception e) {
                    throw new CAdESLtSigner.SigningException("Failed to compute the signature value", e);
                }
            }
        };
    }

    /**
     * A key on a signature token (PKCS#11 smartcard or HSM). The token
     * computes the signature; the key never leaves it.
     *
     * @param token the open token connection, closed by {@link #close()}
     * @param entry the key on that token
     */
    static SigningKey token(SignatureTokenConnection token, DSSPrivateKeyEntry entry) {
        return new SigningKey() {
            @Override
            public X509Certificate certificate() {
                return entry.getCertificate().getCertificate();
            }

            @Override
            public EncryptionAlgorithm encryptionAlgorithm() {
                return entry.getEncryptionAlgorithm();
            }

            @Override
            public SignatureValue sign(ToBeSigned data, DigestAlgorithm digest) {
                try {
                    return token.sign(data, digest, entry);
                } catch (RuntimeException e) {
                    throw new CAdESLtSigner.SigningException(
                            "The token failed to compute the signature value", e);
                }
            }

            @Override
            public void close() {
                token.close();
            }
        };
    }
}
