package com.example.cades;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import picocli.CommandLine.Option;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A signing key on a PKCS#11 token: a smartcard, USB token or HSM, reached
 * through the vendor's PKCS#11 library. This is how qualified signatures
 * are made: the key is generated on a certified device and never leaves it.
 */
class Pkcs11Options {

    @Option(names = "--pkcs11-lib", paramLabel = "<path>",
            description = "PKCS#11 library of the smartcard or HSM, e.g. "
                    + "/usr/lib/softhsm/libsofthsm2.so or opensc-pkcs11.so")
    File library;

    @Option(names = "--pkcs11-slot", paramLabel = "<id>",
            description = "slot ID of the token (see pkcs11-tool --list-slots); "
                    + "default: the first slot with a token")
    Integer slot;

    @Option(names = "--pkcs11-slot-index", paramLabel = "<n>",
            description = "position of the slot in the library's slot list, "
                    + "instead of --pkcs11-slot")
    Integer slotIndex;

    @Option(names = "--pkcs11-key", paramLabel = "<alias>",
            description = "alias (label) of the signing key; needed when the token "
                    + "holds more than one (see cades pkcs11 list)")
    String key;

    @Option(names = "--pin", arity = "0..1", fallbackValue = SecretResolver.PROMPT,
            description = "PIN of the token; asked for on the console when the token "
                    + "needs one and none is given" + SecretResolver.FORMS)
    String pin;

    @Option(names = "--signer-chain", paramLabel = "<pem>",
            description = "CA certificates (PEM or PKCS#12) completing the signer's chain "
                    + "when the token holds only the signer certificate")
    File chainFile;

    boolean isSet() {
        return library != null;
    }

    /** Opens the token; the caller closes it. */
    Pkcs11SignatureToken open() {
        if (slot != null && slotIndex != null) {
            throw new IllegalArgumentException("use only one of --pkcs11-slot and --pkcs11-slot-index");
        }
        if (!library.isFile()) {
            throw new IllegalArgumentException("PKCS#11 library not found: " + library);
        }
        // The PIN is resolved only when the token asks, so tokens with a
        // PIN pad or without login need none.
        String pinValue = pin != null ? pin : SecretResolver.PROMPT;
        return new Pkcs11SignatureToken(library.getAbsolutePath(),
                () -> new SecretResolver().resolve("--pin", pinValue),
                slot == null ? -1 : slot,
                slotIndex == null ? -1 : slotIndex,
                null);
    }

    /**
     * Opens the token and resolves the signing key and its chain.
     *
     * @return credentials without a TSA and without CA keys: a token's CA
     *         is never at hand, so LT needs online revocation data
     */
    SigningCredentials resolve(KeystoreOptions keystore) {
        Pkcs11SignatureToken token = open();
        try {
            DSSPrivateKeyEntry entry = select(token.getKeys());
            List<X509Certificate> pool = new ArrayList<>();
            for (CertificateToken certificate : entry.getCertificateChain()) {
                pool.add(certificate.getCertificate());
            }
            if (chainFile != null) {
                char[] password = keystore.usesDefaultPassword() ? new char[0] : keystore.password();
                pool.addAll(CredentialFile.load(chainFile, password, "signer-chain").chain());
            }
            X509Certificate leaf = entry.getCertificate().getCertificate();
            List<X509Certificate> chain = SigningCredentials.buildChain(leaf, pool);
            return new SigningCredentials(SigningKey.token(token, entry), chain,
                    null, List.of(), List.of());
        } catch (RuntimeException e) {
            token.close();
            throw e;
        }
    }

    private DSSPrivateKeyEntry select(List<DSSPrivateKeyEntry> keys) {
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("the PKCS#11 token holds no private key "
                    + "with a certificate");
        }
        if (key == null) {
            if (keys.size() > 1) {
                throw new IllegalArgumentException("the token holds " + keys.size()
                        + " keys; choose one with --pkcs11-key: " + aliases(keys));
            }
            return keys.getFirst();
        }
        return keys.stream()
                .filter(candidate -> key.equals(alias(candidate)))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no key with alias '" + key
                        + "' on the token; available: " + aliases(keys)));
    }

    static String alias(DSSPrivateKeyEntry entry) {
        return entry instanceof KSPrivateKeyEntry ks ? ks.getAlias() : "?";
    }

    private static String aliases(List<DSSPrivateKeyEntry> keys) {
        return keys.stream().map(Pkcs11Options::alias).collect(Collectors.joining(", "));
    }
}
