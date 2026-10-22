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

    @Option(names = "--keystore-password",
            description = "keystore password (default: " + DEFAULT_PASSWORD + ")")
    String keystorePassword;

    @Option(names = "--no-keystore-trust",
            description = "Ignore certificates from the keystore as trust anchors. "
                    + "Only use system trust store or certificates embedded in the signature.")
    boolean noKeystoreTrust;

    char[] password() {
        return keystorePassword == null
                ? DEFAULT_PASSWORD.toCharArray()
                : keystorePassword.toCharArray();
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
