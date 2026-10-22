package com.example.cades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.FileOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignCommandTest {

    private static final char[] PASSWORD = "secret".toCharArray();

    @TempDir
    static Path shared;

    private static TestPki pki;

    @TempDir
    Path dir;

    private Path document;

    @BeforeAll
    static void createPki() {
        pki = TestPki.create(shared.resolve("pki.p12").toString(), PASSWORD);
    }

    @org.junit.jupiter.api.BeforeEach
    void writeDocument() throws Exception {
        document = Files.writeString(dir.resolve("doc.txt"), "hello");
    }

    @Test
    @DisplayName("signing without any keystore is refused")
    void refusesToSignWithoutKeys() {
        Run run = sign(document.toString());

        assertNotEquals(0, run.exitCode);
        assertTrue(run.error.contains("a signing keystore is required"), run.error);
        assertFalse(Files.exists(Path.of(document + ".p7s")));
    }

    @Test
    @DisplayName("a missing --keystore is reported, not silently created")
    void doesNotCreateMissingKeystore() {
        Path missing = dir.resolve("missing.p12");

        Run run = sign(document.toString(), "--keystore", missing.toString());

        assertNotEquals(0, run.exitCode);
        assertTrue(run.error.contains("keystore not found"), run.error);
        assertFalse(Files.exists(missing));
    }

    @Test
    @DisplayName("--generate-keystore creates a keystore, signs at LT and never overwrites")
    void generatesKeystore() {
        Path generated = dir.resolve("new.p12");

        Run first = sign(document.toString(), "--generate-keystore", generated.toString());
        assertEquals(0, first.exitCode, first.error);
        assertTrue(Files.isRegularFile(generated));
        assertLongTerm(TestPki.load(generated.toString(), null).root().certificate());

        Run second = sign(document.toString(), "--generate-keystore", generated.toString());
        assertNotEquals(0, second.exitCode);
        assertTrue(second.error.contains("refusing to overwrite"), second.error);
    }

    @Test
    @DisplayName("separate signer (PKCS#12) and TSA (PEM) files reach LT")
    void signsWithSeparateFiles() throws Exception {
        Path signer = writePkcs12(dir.resolve("signer.p12"), pki.signer(), pki.root());
        // Encrypted PKCS#8 key and no file extension, as a web upload would be.
        Path tsa = writePem(dir.resolve("tsa"), true, pki.tsa(), pki.root());

        Run run = sign(document.toString(),
                "--signer", signer.toString(), "--signer-password", "secret",
                "--tsa", tsa.toString(), "--tsa-password", "secret");

        assertEquals(0, run.exitCode, run.error);
        assertLongTerm(pki.root().certificate());
    }

    @Test
    @DisplayName("offline LT without the CA key fails clearly; B-T still works")
    void requiresCaKeyForOfflineLt() throws Exception {
        Path signer = writePem(dir.resolve("signer.pem"), false, pki.signer());
        appendCertificate(signer, pki.root());
        Path tsa = writePem(dir.resolve("tsa.pem"), false, pki.tsa());
        appendCertificate(tsa, pki.root());

        Run lt = sign(document.toString(), "--signer", signer.toString(), "--tsa", tsa.toString());
        assertNotEquals(0, lt.exitCode);
        assertTrue(lt.error.contains("issuing CA's private key"), lt.error);

        Run bt = sign(document.toString(), "--signer", signer.toString(), "--tsa", tsa.toString(),
                "--level", "B-T");
        assertEquals(0, bt.exitCode, bt.error);
    }

    @Test
    @DisplayName("--signer without a TSA is refused above level B")
    void requiresTsaWithSigner() throws Exception {
        Path signer = writePkcs12(dir.resolve("signer.p12"), pki.signer(), pki.root());

        Run run = sign(document.toString(), "--signer", signer.toString(),
                "--signer-password", "secret");

        assertNotEquals(0, run.exitCode);
        assertTrue(run.error.contains("needs a timestamp"), run.error);

        Run basic = sign(document.toString(), "--signer", signer.toString(),
                "--signer-password", "secret", "--level", "B");
        assertEquals(0, basic.exitCode, basic.error);
    }

    @Test
    @DisplayName("a certificate-only TSA file needs --tsa-url, and is accepted with it")
    void certificateOnlyTsaFileNeedsUrl() throws Exception {
        Path signer = writePkcs12(dir.resolve("signer.p12"), pki.signer(), pki.root());
        Path tsaChain = writePem(dir.resolve("tsa-chain.pem"), false);
        appendCertificate(tsaChain, pki.tsa());
        appendCertificate(tsaChain, pki.root());

        Run local = sign(document.toString(), "--signer", signer.toString(),
                "--signer-password", "secret", "--tsa", tsaChain.toString());
        assertNotEquals(0, local.exitCode);
        assertTrue(local.error.contains("holds only certificates"), local.error);

        // Unreachable URL: getting past option checks to the network call
        // proves the combination is accepted.
        Run online = sign(document.toString(), "--signer", signer.toString(),
                "--signer-password", "secret", "--tsa", tsaChain.toString(),
                "--tsa-url", "http://127.0.0.1:9/tsr", "--level", "B-T");
        assertNotEquals(0, online.exitCode);
        assertFalse(online.error.contains("mutually exclusive"), online.error);
        assertFalse(online.error.contains("holds only certificates"), online.error);
    }

    @Test
    @DisplayName("a PEM damaged by copy-paste is reported as such")
    void reportsDamagedPem() throws Exception {
        Path signer = writePem(dir.resolve("signer.pem"), false, pki.signer());
        List<String> lines = new ArrayList<>(Files.readAllLines(signer));
        // Drop one base64 character inside the certificate, as a bad paste would.
        int line = lines.indexOf("-----BEGIN CERTIFICATE-----") + 3;
        lines.set(line, lines.get(line).substring(1));
        Files.write(signer, lines);

        Run run = sign(document.toString(), "--signer", signer.toString(), "--level", "B");

        assertNotEquals(0, run.exitCode);
        assertTrue(run.error.contains("damaged"), run.error);
    }

    @Test
    @DisplayName("B and B-T pass the self-check for their own level, not as failed B-LT")
    void selfCheckJudgesTheRequestedLevel() {
        Path keystore = dir.resolve("keys.p12");
        assertEquals(0, sign(document.toString(), "--generate-keystore", keystore.toString()).exitCode);
        java.security.cert.X509Certificate root = TestPki.load(keystore.toString(), null).root().certificate();

        for (var level : List.of(SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T)) {
            Run run = sign(document.toString(), "--keystore", keystore.toString(),
                    "--level", level == SignatureLevel.CAdES_BASELINE_B ? "B" : "B-T");
            assertEquals(0, run.exitCode, run.error);

            CAdESLtVerifier.Result result = new CAdESLtVerifier(root).verify(
                    new FileDocument(document + ".p7s"), new FileDocument(document.toFile()));
            assertEquals(level, result.level());
            // No revocation data at these levels, so full offline validation cannot conclude...
            assertEquals(Indication.INDETERMINATE, result.indication());
            // ...but the signature is everything its level promises.
            assertTrue(result.isSignatureIntact());
            assertTrue(result.isChainTrusted());
            assertEquals(level == SignatureLevel.CAdES_BASELINE_T, result.hasValidSignatureTimestamp());
            assertTrue(result.isPassedFor(level));
            assertFalse(result.isPassedFor(SignatureLevel.CAdES_BASELINE_LT));
        }
    }

    private void assertLongTerm(java.security.cert.X509Certificate root) {
        CAdESLtVerifier.Result result = new CAdESLtVerifier(root).verify(
                new FileDocument(document + ".p7s"), new FileDocument(document.toFile()));
        assertEquals(SignatureLevel.CAdES_BASELINE_LT, result.level());
        assertEquals(Indication.TOTAL_PASSED, result.indication());
    }

    private static Run sign(String... args) {
        List<String> full = new ArrayList<>(List.of("sign"));
        full.addAll(List.of(args));
        StringBuilder error = new StringBuilder();
        CommandLine commandLine = new CommandLine(new Main());
        commandLine.setExecutionExceptionHandler((exception, cmd, parsed) -> {
            error.append(exception.getMessage());
            return 1;
        });
        int exitCode = commandLine.execute(full.toArray(String[]::new));
        return new Run(exitCode, error.toString());
    }

    private record Run(int exitCode, String error) {
    }

    /** The first entry is the party's own; the rest are CA keys. */
    private static Path writePkcs12(Path target, TestPki.CertificateAndKey... entries)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        for (int i = 0; i < entries.length; i++) {
            keyStore.setKeyEntry(i == 0 ? "key" : "ca" + i, entries[i].privateKey(), PASSWORD,
                    new Certificate[]{entries[i].certificate()});
        }
        try (FileOutputStream out = new FileOutputStream(target.toFile())) {
            keyStore.store(out, PASSWORD);
        }
        return target;
    }

    private static Path writePem(Path target, boolean encrypt,
                                 TestPki.CertificateAndKey... entries) throws Exception {
        StringWriter text = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
            for (TestPki.CertificateAndKey entry : entries) {
                writer.writeObject(entry.certificate());
                writer.writeObject(new JcaPKCS8Generator(entry.privateKey(), encrypt
                        ? new JceOpenSSLPKCS8EncryptorBuilder(PKCSObjectIdentifiers.des_EDE3_CBC)
                                .setProvider(TestPki.BC).setPassword(PASSWORD).build()
                        : null));
            }
        }
        return Files.writeString(target, text.toString(), StandardCharsets.US_ASCII);
    }

    private static void appendCertificate(Path pem, TestPki.CertificateAndKey entry)
            throws Exception {
        StringWriter text = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
            writer.writeObject(entry.certificate());
        }
        Files.writeString(pem, text.toString(), StandardCharsets.US_ASCII,
                java.nio.file.StandardOpenOption.APPEND);
    }
}
