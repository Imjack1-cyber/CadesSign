package com.example.cades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Signs with keys on a SoftHSM2 token, through the same PKCS#11 path a
 * smartcard or HSM takes. Skipped when SoftHSM2 is not installed; set
 * SOFTHSM2_LIB and SOFTHSM2_UTIL to use a copy outside the usual paths.
 * The pom points SOFTHSM2_CONF into target/, so no system state is touched.
 */
class Pkcs11IT {

    private static final String PIN = "1234";
    private static final char[] PASSWORD = "secret".toCharArray();

    @TempDir
    static Path shared;

    private static String library;
    private static String slot;
    private static TestPki pki;
    private static TestPki otherPki;
    private static Path pinFile;
    private static Path tsaFile;
    private static Path passwordFile;

    @TempDir
    Path dir;

    private Path document;

    @BeforeAll
    static void initializeToken() throws Exception {
        Optional<String> lib = firstExisting(System.getenv("SOFTHSM2_LIB"),
                "/usr/lib/softhsm/libsofthsm2.so",
                "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/usr/lib64/pkcs11/libsofthsm2.so",
                "/usr/local/lib/softhsm/libsofthsm2.so",
                "/opt/homebrew/lib/softhsm/libsofthsm2.so");
        String conf = System.getenv("SOFTHSM2_CONF");
        assumeTrue(lib.isPresent(), "SoftHSM2 library not found");
        assumeTrue(conf != null, "SOFTHSM2_CONF is not set (the pom sets it for failsafe)");
        library = lib.get();

        Path tokens = Files.createDirectories(shared.resolve("tokens"));
        Files.createDirectories(Path.of(conf).getParent());
        Files.writeString(Path.of(conf), "directories.tokendir = " + tokens
                + "\nobjectstore.backend = file\nlog.level = ERROR\n");

        String util = Optional.ofNullable(System.getenv("SOFTHSM2_UTIL")).orElse("softhsm2-util");
        String output = run(util, "--module", library, "--init-token", "--free",
                "--label", "cades-test", "--so-pin", "12345678", "--pin", PIN);
        Matcher reassigned = Pattern.compile("reassigned to slot (\\d+)").matcher(output);
        assertTrue(reassigned.find(), output);
        slot = reassigned.group(1);

        pki = TestPki.create(shared.resolve("pki.p12").toString(), PASSWORD);
        Provider provider = Security.getProvider("SunPKCS11")
                .configure("--name=import\nlibrary=" + library + "\nslot=" + slot + "\n");
        KeyStore token = KeyStore.getInstance("PKCS11", provider);
        token.load(null, PIN.toCharArray());
        token.setKeyEntry("signer", pki.signer().privateKey(), null,
                new Certificate[]{pki.signer().certificate(), pki.root().certificate()});
        // A second key with only its own certificate, as many cards hold it:
        // the chain then comes from --signer-chain.
        otherPki = TestPki.create(shared.resolve("other.p12").toString(), PASSWORD);
        token.setKeyEntry("leaf-only", otherPki.signer().privateKey(), null,
                new Certificate[]{otherPki.signer().certificate()});

        pinFile = Files.writeString(shared.resolve("pin"), PIN + "\n");
        passwordFile = Files.writeString(shared.resolve("password"), "secret\n");
        // The in-process TSA's key, plus the root key that mints the
        // revocation data for offline LT.
        tsaFile = shared.resolve("tsa.p12");
        KeyStore tsa = KeyStore.getInstance("PKCS12");
        tsa.load(null, null);
        tsa.setKeyEntry("tsa", pki.tsa().privateKey(), PASSWORD,
                new Certificate[]{pki.tsa().certificate(), pki.root().certificate()});
        tsa.setKeyEntry("root", pki.root().privateKey(), PASSWORD,
                new Certificate[]{pki.root().certificate()});
        try (FileOutputStream out = new FileOutputStream(tsaFile.toFile())) {
            tsa.store(out, PASSWORD);
        }
    }

    @BeforeEach
    void writeDocument() throws Exception {
        document = Files.writeString(dir.resolve("doc.txt"), "hello");
    }

    @Test
    @DisplayName("pkcs11 list shows every key with its certificate")
    void listsKeys() {
        Cli.Run run = Cli.run("pkcs11", "list", "--pkcs11-lib", library,
                "--pkcs11-slot", slot, "--pin", "file:" + pinFile);

        assertEquals(0, run.exitCode(), run.toString());
        assertTrue(run.out().contains("Key signer"), run.out());
        assertTrue(run.out().contains("Key leaf-only"), run.out());
        assertTrue(run.out().contains("CN=CAdES Demo Signer"), run.out());
        assertTrue(run.out().contains("Qualified  : no"), run.out());
    }

    @Test
    @DisplayName("a key on the token signs at LT")
    void signsAtLongTerm() {
        Cli.Run run = sign("--pkcs11-key", "signer");

        assertEquals(0, run.exitCode(), run.toString());
        assertLongTerm();
    }

    @Test
    @DisplayName("--signer-chain completes a chain the token does not hold")
    void signerChainFile() throws Exception {
        StringWriter pem = new StringWriter();
        try (var writer = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(pem)) {
            writer.writeObject(otherPki.root().certificate());
        }
        Path chain = Files.writeString(dir.resolve("root.pem"), pem.toString(), StandardCharsets.US_ASCII);

        // B-T: the TSA file holds no key of the other PKI's CA to mint LT data with.
        Cli.Run run = sign("--pkcs11-key", "leaf-only", "--signer-chain", chain.toString(),
                "--level", "B-T");

        assertEquals(0, run.exitCode(), run.toString());
        CAdESLtVerifier.Result result = new CAdESLtVerifier(List.of(
                otherPki.root().certificate(), pki.root().certificate())).verify(
                new FileDocument(document + ".p7s"), new FileDocument(document.toFile()));
        assertTrue(result.isPassedFor(SignatureLevel.CAdES_BASELINE_T));
        assertTrue(result.isChainTrusted());
    }

    @Test
    @DisplayName("with several keys and no --pkcs11-key, the aliases are listed")
    void ambiguousKey() {
        Cli.Run run = sign();

        assertEquals(2, run.exitCode(), run.toString());
        assertTrue(run.err().contains("--pkcs11-key") && run.err().contains("leaf-only"), run.toString());
    }

    @Test
    @DisplayName("an unknown alias is a usage error naming the available ones")
    void unknownKey() {
        Cli.Run run = sign("--pkcs11-key", "nope");

        assertEquals(2, run.exitCode(), run.toString());
        assertTrue(run.err().contains("available: "), run.toString());
    }

    @Test
    @DisplayName("a wrong PIN is an error (3) and no signature is written")
    void wrongPin() throws Exception {
        Path wrong = Files.writeString(dir.resolve("wrong-pin"), "9999\n");

        Cli.Run run = Cli.run("sign", document.toString(), "--pkcs11-lib", library,
                "--pkcs11-slot", slot, "--pin", "file:" + wrong, "--pkcs11-key", "signer",
                "--tsa", tsaFile.toString(), "--tsa-password", "file:" + passwordFile);

        assertEquals(3, run.exitCode(), run.toString());
        assertTrue(Files.notExists(Path.of(document + ".p7s")));
    }

    @Test
    @DisplayName("--pkcs11-lib cannot be combined with --keystore")
    void exclusiveWithKeystore() {
        Cli.Run run = sign("--pkcs11-key", "signer", "--keystore", shared.resolve("pki.p12").toString());

        assertEquals(2, run.exitCode(), run.toString());
        assertTrue(run.err().contains("use only one of"), run.toString());
    }

    private Cli.Run sign(String... extra) {
        List<String> args = new java.util.ArrayList<>(List.of("sign", document.toString(),
                "--pkcs11-lib", library, "--pkcs11-slot", slot, "--pin", "file:" + pinFile,
                "--tsa", tsaFile.toString(), "--tsa-password", "file:" + passwordFile));
        args.addAll(List.of(extra));
        return Cli.run(args.toArray(String[]::new));
    }

    private void assertLongTerm() {
        CAdESLtVerifier.Result result = new CAdESLtVerifier(pki.root().certificate()).verify(
                new FileDocument(document + ".p7s"), new FileDocument(document.toFile()));
        assertEquals(SignatureLevel.CAdES_BASELINE_LT, result.level());
        assertEquals(Indication.TOTAL_PASSED, result.indication());
    }

    private static Optional<String> firstExisting(String... candidates) {
        return Stream.of(candidates)
                .filter(candidate -> candidate != null && Files.isRegularFile(Path.of(candidate)))
                .findFirst();
    }

    private static String run(String... command) throws Exception {
        Process process;
        try {
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
        } catch (java.io.IOException e) {
            assumeTrue(false, command[0] + " not found");
            throw e;
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "timed out: " + command[0]);
        assertEquals(0, process.exitValue(), output);
        return output;
    }
}
