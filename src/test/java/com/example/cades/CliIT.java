package com.example.cades;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The shaded jar as a process: packaging, exit codes, and stdout/stderr discipline. */
class CliIT {

    private static final Map<String, String> PASSWORD = Map.of("CADES_IT_PASSWORD", "secret");

    @TempDir
    static Path dir;

    private static Path keystore;
    private static Path document;

    @BeforeAll
    static void signOnce() throws Exception {
        keystore = dir.resolve("pki.p12");
        document = Files.writeString(dir.resolve("doc.txt"), "hello");
        Cli.Run run = Jar.run(PASSWORD, "sign", document.toString(),
                "--generate-keystore", keystore.toString(), "--keystore-password", "env:CADES_IT_PASSWORD");
        assertEquals(0, run.exitCode(), run.toString());
    }

    @Test
    @DisplayName("--version names the CLI, DSS and BouncyCastle versions")
    void version() throws Exception {
        Cli.Run run = Jar.run("--version");

        assertEquals(0, run.exitCode(), run.toString());
        assertTrue(run.out().matches("(?s)cades \\d+\\.\\d+\\.\\d+.*DSS 6\\.\\d+.*BouncyCastle 1\\.\\d+.*"),
                run.out());
    }

    @Test
    @DisplayName("every command has --help, with its exit codes where they matter")
    void help() throws Exception {
        for (String[] command : new String[][]{{"sign"}, {"verify"}, {"pkcs11", "list"}, {"tl", "refresh"}}) {
            String[] args = java.util.Arrays.copyOf(command, command.length + 1);
            args[command.length] = "--help";
            Cli.Run run = Jar.run(args);
            assertEquals(0, run.exitCode(), run.toString());
            assertTrue(run.out().startsWith("Usage: cades " + String.join(" ", command)), run.out());
        }
        assertTrue(Jar.run("verify", "--help").out().contains("Exit codes:"));
    }

    @Test
    @DisplayName("the jar verifies what it signed (exit 0) and rejects changed content (exit 1)")
    void roundTrip() throws Exception {
        Cli.Run valid = Jar.run(PASSWORD, "verify", document.toString(), document + ".p7s",
                "--keystore", keystore.toString(), "--keystore-password", "env:CADES_IT_PASSWORD",
                "--report", "json");
        assertEquals(0, valid.exitCode(), valid.toString());
        assertTrue(valid.out().strip().startsWith("{\"level\":\"CAdES-BASELINE-LT\""), valid.toString());

        Path changed = Files.copy(document, dir.resolve("changed.txt"));
        Files.writeString(changed, "!", StandardOpenOption.APPEND);
        Cli.Run invalid = Jar.run(PASSWORD, "verify", changed.toString(), document + ".p7s",
                "--keystore", keystore.toString(), "--keystore-password", "env:CADES_IT_PASSWORD");
        assertEquals(1, invalid.exitCode(), invalid.toString());
    }

    @Test
    @DisplayName("DSS logging goes to stderr only, at WARN unless -v is given")
    void loggingStaysOnStderr() throws Exception {
        Cli.Run quiet = Jar.run(PASSWORD, "verify", document.toString(), document + ".p7s",
                "--keystore", keystore.toString(), "--keystore-password", "env:CADES_IT_PASSWORD");
        assertFalse(quiet.out().contains("[main]"), quiet.toString());
        assertFalse(quiet.err().contains(" INFO "), quiet.toString());

        Cli.Run verbose = Jar.run(PASSWORD, "verify", "-v", document.toString(), document + ".p7s",
                "--keystore", keystore.toString(), "--keystore-password", "env:CADES_IT_PASSWORD");
        assertFalse(verbose.out().contains("[main]"), verbose.toString());
        assertTrue(verbose.err().contains(" INFO "), verbose.toString());
    }

    @Test
    @EnabledIfSystemProperty(named = "cades.slowTests", matches = "true")
    @DisplayName("a 1 GB document is signed detached within a 256 MB heap (-Dcades.slowTests=true)")
    void largeDocumentStreams() throws Exception {
        Path large = dir.resolve("large.bin");
        try (RandomAccessFile file = new RandomAccessFile(large.toFile(), "rw")) {
            file.setLength(1024L * 1024 * 1024);
        }
        Map<String, String> environment = new java.util.HashMap<>(PASSWORD);
        environment.put("JAVA_TOOL_OPTIONS", "-Xmx256m");
        try {
            Cli.Run run = Jar.run(environment, "sign", large.toString(), "--keystore", keystore.toString(),
                    "--keystore-password", "env:CADES_IT_PASSWORD");
            assertEquals(0, run.exitCode(), run.toString());
        } finally {
            Files.deleteIfExists(large);
        }
    }

    @Test
    @DisplayName("usage errors exit 2, unusable files exit 3")
    void exitCodes() throws Exception {
        assertEquals(2, Jar.run("sign", "--level", "X", document.toString()).exitCode());
        assertEquals(2, Jar.run("verify", dir.resolve("absent.p7s").toString()).exitCode());

        Path garbage = Files.writeString(dir.resolve("garbage.p12"), "not a keystore");
        Cli.Run run = Jar.run(PASSWORD, "verify", document.toString(), document + ".p7s",
                "--keystore", garbage.toString(), "--keystore-password", "env:CADES_IT_PASSWORD");
        assertEquals(3, run.exitCode(), run.toString());
    }
}
