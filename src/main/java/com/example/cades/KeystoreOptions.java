package com.example.cades;

import picocli.CommandLine.Option;

import java.io.File;

/**
 * Keystore options shared by every subcommand, so the test PKI can
 * live anywhere and under any password.
 */
class KeystoreOptions {

    static final String DEFAULT_PASSWORD = "passwort";

    @Option(names = "--keystore",
            description = "PKCS#12 keystore holding the test PKI "
                    + "(root, signer and tsa entries). Required by sign unless "
                    + "--signer or --generate-keystore is given; optional for "
                    + "verify, which then uses the system trust store")
    File keystore;

    @Option(names = "--keystore-password", arity = "0..1",
            fallbackValue = SecretResolver.PROMPT,
            description = "keystore password (default: the test-PKI password "
                    + DEFAULT_PASSWORD + ")" + SecretResolver.FORMS)
    String keystorePassword;

    @Option(names = "--no-keystore-trust",
            description = "Ignore certificates from the keystore as trust anchors. "
                    + "Only use system trust store or certificates embedded in the signature.")
    boolean noKeystoreTrust;

    private char[] resolvedPassword;

    /**
     * The keystore password, resolved once so that a prompt or warning
     * appears only once.
     */
    char[] password() {
        if (resolvedPassword == null) {
            resolvedPassword = new SecretResolver().resolve("--keystore-password", keystorePassword);
        }
        if (resolvedPassword == null) {
            System.err.println("Note: no --keystore-password given, using the test-PKI "
                    + "default password.");
            resolvedPassword = DEFAULT_PASSWORD.toCharArray();
        }
        return resolvedPassword.clone();
    }

    /** Whether the password falls back to the test-PKI default. */
    boolean usesDefaultPassword() {
        return keystorePassword == null;
    }

    String keystorePath() {
        return keystore == null ? null : keystore.getPath();
    }

    TestPki loadPki() {
        return keystore == null
                ? TestPki.generate()
                : TestPki.generate(keystore.getPath(), password());
    }

    CAdESLtVerifier loadVerifier() {
        if (keystore == null) {
            return CAdESLtVerifier.fromSystemTrustStore();
        }
        if (noKeystoreTrust) {
            // Use keystore for signing keys but ignore its certificates as trust anchors
            return CAdESLtVerifier.fromKeystoreIgnoringTrustAnchors(keystorePath(), password());
        }
        return CAdESLtVerifier.fromKeystore(keystorePath(), password());
    }
}
