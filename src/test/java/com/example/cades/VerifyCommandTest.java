package com.example.cades;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifyCommandTest {

    @TempDir
    static Path dir;

    private static Path keystore;
    private static Path document;
    private static Path detached;
    private static Path enveloping;

    @BeforeAll
    static void sign() throws Exception {
        keystore = dir.resolve("pki.p12");
        document = Files.writeString(dir.resolve("doc.txt"), "hello");
        detached = dir.resolve("doc.txt.p7s");
        enveloping = dir.resolve("doc.txt.enveloping.p7s");

        Cli.Run generated = Cli.run("sign", document.toString(),
                "--generate-keystore", keystore.toString(), "--keystore-password", "file:" + password());
        assertEquals(0, generated.exitCode(), generated.toString());

        Cli.Run envelopingRun = Cli.run("sign", document.toString(), "-o", enveloping.toString(),
                "--packaging", "enveloping",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password());
        assertEquals(0, envelopingRun.exitCode(), envelopingRun.toString());
    }

    private static Path password() throws Exception {
        Path file = dir.resolve("password");
        if (!Files.exists(file)) {
            Files.writeString(file, "secret\n");
        }
        return file;
    }

    private static Cli.Run verify(String... args) throws Exception {
        String[] full = new String[args.length + 5];
        full[0] = "verify";
        System.arraycopy(args, 0, full, 1, args.length);
        full[args.length + 1] = "--keystore";
        full[args.length + 2] = keystore.toString();
        full[args.length + 3] = "--keystore-password";
        full[args.length + 4] = "file:" + password();
        return Cli.run(full);
    }

    @Test
    @DisplayName("a valid detached signature exits 0 with the summary on stdout")
    void validDetached() throws Exception {
        Cli.Run run = verify(document.toString(), detached.toString());

        assertEquals(0, run.exitCode(), run.toString());
        assertTrue(run.out().contains("Level reached : CAdES-BASELINE-LT"), run.toString());
        assertTrue(run.out().contains("TOTAL_PASSED"), run.toString());
    }

    @Test
    @DisplayName("an enveloping signature verifies from a single argument")
    void validEnveloping() throws Exception {
        Cli.Run run = verify(enveloping.toString());

        assertEquals(0, run.exitCode(), run.toString());
        assertTrue(run.out().contains("TOTAL_PASSED"), run.toString());
    }

    @Test
    @DisplayName("changed content exits 1")
    void tamperedContent() throws Exception {
        Path changed = Files.copy(document, dir.resolve("changed.txt"));
        Files.writeString(changed, "!", StandardOpenOption.APPEND);

        Cli.Run run = verify(changed.toString(), detached.toString());

        assertEquals(1, run.exitCode(), run.toString());
        assertTrue(run.out().contains("TOTAL_FAILED"), run.toString());
    }

    @Test
    @DisplayName("a signature from an untrusted PKI exits 1")
    void untrustedAnchor() throws Exception {
        Path other = dir.resolve("other.p12");
        TestPki.create(other.toString(), "secret".toCharArray());

        Cli.Run run = Cli.run("verify", document.toString(), detached.toString(),
                "--keystore", other.toString(), "--keystore-password", "file:" + password());

        assertEquals(1, run.exitCode(), run.toString());
    }

    @Test
    @DisplayName("a missing signature file is a usage error (2)")
    void missingFile() throws Exception {
        Cli.Run run = verify(document.toString(), dir.resolve("absent.p7s").toString());

        assertEquals(2, run.exitCode(), run.toString());
        assertTrue(run.err().contains("signature file not found"), run.toString());
    }

    @Test
    @DisplayName("a wrong keystore password is an error (3) that names the cause")
    void wrongPassword() throws Exception {
        Path wrong = Files.writeString(dir.resolve("wrong"), "nope\n");
        Cli.Run run = Cli.run("verify", document.toString(), detached.toString(),
                "--keystore", keystore.toString(), "--keystore-password", "file:" + wrong);

        assertEquals(3, run.exitCode(), run.toString());
        assertTrue(run.err().startsWith("Error: Unable to load"), run.toString());
    }

    @Test
    @DisplayName("--report json is a single JSON object with the key facts")
    void jsonReport() throws Exception {
        Cli.Run run = verify(document.toString(), detached.toString(), "--report", "json");

        assertEquals(0, run.exitCode(), run.toString());
        String json = run.out().strip();
        assertTrue(json.startsWith("{") && json.endsWith("}"), json);
        assertEquals(1, json.lines().count(), json);
        assertTrue(json.contains("\"level\":\"CAdES-BASELINE-LT\""), json);
        assertTrue(json.contains("\"indication\":\"TOTAL_PASSED\""), json);
        assertTrue(json.contains("\"passed\":true"), json);
        assertTrue(json.contains("\"signedBy\":\"CAdES Demo Signer\""), json);
        assertTrue(json.contains("\"type\":\"SIGNATURE_TIMESTAMP\""), json);
        assertTrue(json.contains("\"errors\":[]"), json);
    }

    @Test
    @DisplayName("--report full prints the DSS XML report")
    void fullReport() throws Exception {
        Cli.Run run = verify(document.toString(), detached.toString(), "--report", "full");

        assertEquals(0, run.exitCode(), run.toString());
        assertTrue(run.out().strip().startsWith("<?xml"), run.out());
    }

    @Test
    @DisplayName("log output stays off stdout")
    void stdoutStaysClean() throws Exception {
        Cli.Run run = verify(document.toString(), detached.toString(), "--report", "json");

        assertTrue(run.out().lines().noneMatch(line -> line.contains("[main]")), run.out());
    }
}
