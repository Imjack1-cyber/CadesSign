package com.example.cades;

import picocli.CommandLine.Option;

import java.io.File;
import java.util.List;

/**
 * Where {@code sign} takes its keys from: a combined test-PKI
 * keystore, separate signer and TSA files, a PKCS#11 token, or a
 * keystore generated on the spot. Signing never falls back to an
 * implicit keystore.
 */
class SigningKeyOptions {

    @Option(names = "--signer",
            description = "signer key and certificate chain as PKCS#12/PFX or PEM, "
                    + "instead of the keystore's signer entry. May also hold the "
                    + "issuing CA's key, which offline LT needs")
    File signerFile;

    @Option(names = "--signer-password", arity = "0..1",
            fallbackValue = SecretResolver.PROMPT,
            description = "password of the --signer file (default: --keystore-password)"
                    + SecretResolver.FORMS)
    String signerPassword;

    @Option(names = "--tsa",
            description = "TSA key and certificate chain as PKCS#12/PFX or PEM for "
                    + "the in-process TSA, instead of the keystore's tsa entry. "
                    + "With --tsa-url, the certificate chain of that online TSA "
                    + "(a key is then not needed)")
    File tsaFile;

    @Option(names = "--tsa-password", arity = "0..1",
            fallbackValue = SecretResolver.PROMPT,
            description = "password of the --tsa file (default: --keystore-password)"
                    + SecretResolver.FORMS)
    String tsaPassword;

    @Option(names = "--generate-keystore", paramLabel = "<path>",
            description = "generate a new test PKI (root, signer, tsa) into this "
                    + "PKCS#12 file, protected by --keystore-password, and sign "
                    + "with it. Never overwrites an existing file")
    File generateKeystore;

    /**
     * Resolves the options into signing credentials.
     *
     * @param keystore the shared keystore options
     * @param pkcs11    the PKCS#11 token options
     * @param onlineTsa whether an online TSA replaces the in-process one
     */
    SigningCredentials resolve(KeystoreOptions keystore, Pkcs11Options pkcs11, boolean onlineTsa) {
        int sources = (keystore.keystore != null ? 1 : 0)
                + (signerFile != null ? 1 : 0)
                + (pkcs11.isSet() ? 1 : 0)
                + (generateKeystore != null ? 1 : 0);
        if (sources == 0) {
            throw new IllegalArgumentException("a signing keystore is required: use "
                    + "--keystore, --signer, --pkcs11-lib, or --generate-keystore <path> "
                    + "to create one");
        }
        if (sources > 1) {
            throw new IllegalArgumentException("use only one of --keystore, --signer, "
                    + "--pkcs11-lib and --generate-keystore");
        }
        SigningCredentials credentials;
        if (pkcs11.isSet()) {
            credentials = pkcs11.resolve(keystore);
        } else if (generateKeystore != null) {
            credentials = TestPki.create(generateKeystore.getPath(), keystore.password())
                    .toCredentials();
            System.out.println("Generated new keystore at " + generateKeystore);
        } else if (keystore.keystore != null) {
            if (!keystore.keystore.isFile()) {
                throw new IllegalArgumentException("keystore not found: " + keystore.keystore
                        + " (use --generate-keystore " + keystore.keystore
                        + " to create it)");
            }
            credentials = TestPki.load(keystore.keystorePath(), keystore.password())
                    .toCredentials();
        } else {
            CredentialFile signer = CredentialFile.load(
                    signerFile, passwordOr("--signer-password", signerPassword, keystore), "signer");
            if (signer.entry() == null) {
                throw new IllegalArgumentException(signerFile + " contains no private key "
                        + "matching its certificate; --signer needs the signing key");
            }
            credentials = new SigningCredentials(SigningKey.software(signer.entry()), signer.chain(),
                    null, List.of(), signer.issuers());
        }

        if (tsaFile != null) {
            CredentialFile tsa = CredentialFile.load(
                    tsaFile, passwordOr("--tsa-password", tsaPassword, keystore), "tsa");
            if (onlineTsa) {
                // The online TSA signs; the file only vouches for its chain.
                if (tsa.entry() != null) {
                    System.out.println("Note: --tsa-url is set, so the TSA key in "
                            + tsaFile + " is not used, only its certificates.");
                }
                credentials = credentials.withTsa(null, tsa.chain(), tsa.issuers());
            } else if (tsa.entry() == null) {
                throw new IllegalArgumentException(tsaFile + " holds only certificates, "
                        + "no TSA key. Add --tsa-url for the online TSA they belong to, "
                        + "or supply a file with the TSA key for the in-process TSA");
            } else {
                credentials = credentials.withTsa(tsa.entry(), tsa.chain(), tsa.issuers());
            }
        } else if (onlineTsa) {
            credentials = credentials.withoutTsa();
        }
        return credentials;
    }

    private static char[] passwordOr(String option, String password, KeystoreOptions keystore) {
        return password != null ? new SecretResolver().resolve(option, password) : keystore.password();
    }
}
