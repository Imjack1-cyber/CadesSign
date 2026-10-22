package com.example.cades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Key material used to produce one signature: the signer, the
 * in-process TSA and any CA keys available to mint offline
 * revocation data.
 *
 * <p>The signer and the TSA may come from different files and even
 * different CAs. Offline revocation works for a certificate only
 * when its issuer's key is among {@link #issuers}; otherwise online
 * revocation endpoints are needed to reach LT.
 *
 * @param signer      signing certificate and its private key
 * @param signerChain signer certificate first, then its issuers
 * @param tsa         TSA certificate and key; {@code null} when an
 *                    online TSA is used
 * @param tsaChain    TSA certificate first, then its issuers; for an
 *                    online TSA the chain it is known to use, or empty
 * @param issuers     CA certificates whose private key is available
 */
public record SigningCredentials(
        TestPki.CertificateAndKey signer,
        List<X509Certificate> signerChain,
        TestPki.CertificateAndKey tsa,
        List<X509Certificate> tsaChain,
        List<TestPki.CertificateAndKey> issuers) {

    public SigningCredentials {
        signerChain = List.copyOf(signerChain);
        tsaChain = List.copyOf(tsaChain);
        issuers = List.copyOf(issuers);
    }

    /** Replaces the TSA, keeping the signer and merging the CA keys. */
    public SigningCredentials withTsa(TestPki.CertificateAndKey newTsa,
                                      List<X509Certificate> newTsaChain,
                                      List<TestPki.CertificateAndKey> moreIssuers) {
        List<TestPki.CertificateAndKey> merged = new ArrayList<>(issuers);
        moreIssuers.stream()
                .filter(candidate -> merged.stream().noneMatch(
                        known -> known.certificate().equals(candidate.certificate())))
                .forEach(merged::add);
        return new SigningCredentials(signer, signerChain, newTsa, newTsaChain, merged);
    }

    /** Drops the in-process TSA, for use with an online TSA. */
    public SigningCredentials withoutTsa() {
        return new SigningCredentials(signer, signerChain, null, List.of(), issuers);
    }

    /** Every certificate of the signer and TSA chains below the trust anchors. */
    public List<X509Certificate> intermediates() {
        Set<X509Certificate> all = new LinkedHashSet<>(signerChain);
        all.addAll(tsaChain);
        all.removeAll(trustAnchors());
        return List.copyOf(all);
    }

    /** The topmost certificate of the signer and TSA chains. */
    public List<X509Certificate> trustAnchors() {
        Set<X509Certificate> anchors = new LinkedHashSet<>();
        anchors.add(signerChain.getLast());
        if (!tsaChain.isEmpty()) {
            anchors.add(tsaChain.getLast());
        }
        return List.copyOf(anchors);
    }

    /**
     * Certificates in either chain whose revocation status cannot be
     * minted offline because their issuer's private key is missing.
     */
    public List<X509Certificate> certificatesWithoutIssuerKey() {
        Set<X509Certificate> all = new LinkedHashSet<>(signerChain);
        all.addAll(tsaChain);
        return all.stream()
                .filter(certificate -> !isSelfSigned(certificate))
                .filter(certificate -> findIssuer(certificate, issuers).isEmpty())
                .toList();
    }

    /**
     * Orders a certificate chain starting at {@code leaf}, picking each
     * issuer from {@code pool} until a self-signed certificate is reached
     * or no issuer is available.
     */
    static List<X509Certificate> buildChain(X509Certificate leaf,
                                            Collection<X509Certificate> pool) {
        List<X509Certificate> chain = new ArrayList<>();
        X509Certificate current = leaf;
        while (current != null && !chain.contains(current)) {
            chain.add(current);
            if (isSelfSigned(current)) {
                break;
            }
            X509Certificate child = current;
            current = pool.stream()
                    .filter(candidate -> isIssuedBy(child, candidate))
                    .findFirst()
                    .orElse(null);
        }
        return chain;
    }

    static Optional<TestPki.CertificateAndKey> findIssuer(
            X509Certificate certificate, Collection<TestPki.CertificateAndKey> candidates) {
        return candidates.stream()
                .filter(candidate -> isIssuedBy(certificate, candidate.certificate()))
                .findFirst();
    }

    static boolean isSelfSigned(X509Certificate certificate) {
        return isIssuedBy(certificate, certificate);
    }

    static boolean isIssuedBy(X509Certificate certificate, X509Certificate issuer) {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            certificate.verify(issuer.getPublicKey(), TestPki.BC);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
