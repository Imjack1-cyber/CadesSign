package com.example.cades;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** gen-pki, tsa, and verification against the system trust store. */
class OtherCommandsTest {

    @TempDir
    static Path dir;

    private static Path keystore;
    private static Path password;
    private static Path document;

    @BeforeAll
    static void createPki() throws Exception {
        keystore = dir.resolve("pki.p12");
        password = Files.writeString(dir.resolve("password"), "secret\n");
        document = Files.writeString(dir.resolve("doc.txt"), "hello");
    }

    @Test
    @DisplayName("gen-pki creates the test PKI once and then reuses it")
    void genPki() {
        Cli.Run first = Cli.run("gen-pki", "--keystore", keystore.toString(),
                "--keystore-password", "file:" + password);
        assertEquals(0, first.exitCode(), first.toString());
        assertTrue(first.out().contains("CN=CAdES Demo Root CA"), first.toString());

        Cli.Run second = Cli.run("gen-pki", "--keystore", keystore.toString(),
                "--keystore-password", "file:" + password);
        assertEquals(0, second.exitCode(), second.toString());
        assertEquals(first.out(), second.out());
    }

    @Test
    @DisplayName("the tsa command serves timestamps that sign reaches B-T with")
    void tsaServer() throws Exception {
        genPki();
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        String[] tsaArgs = {"tsa", "--keystore", keystore.toString(), "--keystore-password", "file:" + password,
                "--port", String.valueOf(port), "--count", "1"};
        CompletableFuture<Integer> server = CompletableFuture.supplyAsync(
                () -> Main.commandLine().execute(tsaArgs));
        awaitPort(port);

        Cli.Run run = Cli.run("sign", document.toString(), "--level", "B-T",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password,
                "--tsa-url", "http://127.0.0.1:" + port + "/");

        assertEquals(0, run.exitCode(), run.toString());
        assertEquals(0, server.get(30, TimeUnit.SECONDS));
    }

    @Test
    @DisplayName("tsa --count 0 is a usage error")
    void tsaCount() {
        assertEquals(2, Cli.run("tsa", "--count", "0").exitCode());
    }

    @Test
    @DisplayName("without --keystore, or with --no-keystore-trust, the test root is not trusted")
    void systemTrustStore() {
        genPki();
        Cli.Run signed = Cli.run("sign", document.toString(), "--keystore", keystore.toString(),
                "--keystore-password", "file:" + password);
        assertEquals(0, signed.exitCode(), signed.toString());

        Cli.Run system = Cli.run("verify", document.toString(), document + ".p7s");
        assertEquals(1, system.exitCode(), system.toString());

        Cli.Run ignored = Cli.run("verify", document.toString(), document + ".p7s", "--no-keystore-trust",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password);
        assertEquals(1, ignored.exitCode(), ignored.toString());

        Cli.Run trusted = Cli.run("verify", document.toString(), document + ".p7s",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password);
        assertEquals(0, trusted.exitCode(), trusted.toString());
    }

    @Test
    @DisplayName("unknown digest, level and packaging names are usage errors that list the valid ones")
    void converters() {
        Cli.Run digest = Cli.run("sign", document.toString(), "--digest", "MD5X");
        assertEquals(2, digest.exitCode(), digest.toString());
        assertTrue(digest.err().contains("SHA256"), digest.toString());

        Cli.Run packaging = Cli.run("sign", document.toString(), "--packaging", "inside");
        assertEquals(2, packaging.exitCode(), packaging.toString());
        assertTrue(packaging.err().contains("detached or enveloping"), packaging.toString());

        Cli.Run report = Cli.run("verify", document.toString(), "--report", "pdf");
        assertEquals(2, report.exitCode(), report.toString());
        assertTrue(report.err().contains("simple, full or json"), report.toString());
    }

    private static void awaitPort(int port) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (System.nanoTime() < deadline) {
            try {
                new Socket("127.0.0.1", port).close();
                return;
            } catch (java.io.IOException notYet) {
                Thread.sleep(50);
            }
        }
        throw new AssertionError("TSA did not start on port " + port);
    }
}
