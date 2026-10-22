package com.example.cades;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Signs against real HTTP services, all on the loopback interface: an
 * RFC 3161 TSA, an OCSP responder and a CRL distribution point. The test
 * PKI's certificates point at them through their AIA and CDP extensions,
 * so {@code --online-revocation} and {@code --strict} are exercised the
 * way they work with a real CA, without needing the internet.
 */
class OnlineSourcesIT {

    @TempDir
    static Path shared;

    private static HttpServer server;
    private static String baseUrl;
    private static TestPki pki;
    private static Path keystore;
    private static Path password;
    private static final AtomicInteger OCSP_REQUESTS = new AtomicInteger();
    private static final AtomicInteger CRL_REQUESTS = new AtomicInteger();

    @TempDir
    Path dir;

    private Path document;

    @BeforeAll
    static void startServices() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();

        keystore = shared.resolve("pki.p12");
        password = Files.writeString(shared.resolve("password"), "secret\n");
        pki = TestPki.create(keystore.toString(), "secret".toCharArray(),
                baseUrl + "/crl", baseUrl + "/ocsp");

        LocalTspSource tsa = new LocalTspSource(pki.tsa(), pki.root().certificate());
        // Revocation data must be dated after the timestamp, as from a real CA
        // that is asked after the TSA has answered.
        OfflineRevocation ca = OfflineRevocation.forIssuers(List.of(pki.root()), tsa::lastIssuedAt);
        Map<BigInteger, X509Certificate> bySerial = Map.of(
                pki.signer().certificate().getSerialNumber(), pki.signer().certificate(),
                pki.tsa().certificate().getSerialNumber(), pki.tsa().certificate());

        server.createContext("/tsa", exchange -> respond(exchange, "application/timestamp-reply",
                () -> tsa.processRequest(exchange.getRequestBody().readAllBytes())));
        server.createContext("/ocsp", exchange -> respond(exchange, "application/ocsp-response", () -> {
            OCSP_REQUESTS.incrementAndGet();
            OCSPReq request = new OCSPReq(exchange.getRequestBody().readAllBytes());
            BigInteger serial = request.getRequestList()[0].getCertID().getSerialNumber();
            return ca.ocspResponseFor(bySerial.get(serial)).orElseThrow();
        }));
        server.createContext("/crl", exchange -> respond(exchange, "application/pkix-crl", () -> {
            CRL_REQUESTS.incrementAndGet();
            return ca.crlFor(pki.signer().certificate()).orElseThrow();
        }));
        server.start();
    }

    @AfterAll
    static void stopServices() {
        server.stop(0);
    }

    @BeforeEach
    void writeDocument() throws Exception {
        document = Files.writeString(dir.resolve("doc.txt"), "hello");
        OCSP_REQUESTS.set(0);
        CRL_REQUESTS.set(0);
    }

    @Test
    @DisplayName("--strict reaches LT from the online TSA and the CA's own OCSP/CRL services")
    void strictReachesLongTerm() {
        Cli.Run run = Cli.run("sign", document.toString(), "--strict",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password,
                "--tsa-url", baseUrl + "/tsa");

        assertEquals(0, run.exitCode(), run.toString());
        assertFalse(run.err().contains("TEST-ONLY"), run.toString());
        assertTrue(OCSP_REQUESTS.get() + CRL_REQUESTS.get() > 0,
                "revocation data must come from the services, not from the CA key");
        assertLongTerm();
    }

    @Test
    @DisplayName("--online-revocation follows the certificates' AIA and CDP without --strict")
    void onlineRevocationFollowsCertificates() {
        Cli.Run run = Cli.run("sign", document.toString(), "--online-revocation",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password,
                "--tsa-url", baseUrl + "/tsa");

        assertEquals(0, run.exitCode(), run.toString());
        assertLongTerm();
    }

    @Test
    @DisplayName("an explicit --ocsp-url and --crl-url replace the certificates' URLs")
    void explicitRevocationUrls() throws Exception {
        // A PKI whose certificates point nowhere: only the explicit URLs can work.
        Path elsewhere = dir.resolve("elsewhere.p12");
        TestPki unreachable = TestPki.create(elsewhere.toString(), "secret".toCharArray(),
                "http://127.0.0.1:9/crl", "http://127.0.0.1:9/ocsp");
        Services own = Services.start(unreachable);
        try {
            String url = own.url();
            Cli.Run run = Cli.run("sign", document.toString(), "--strict",
                    "--keystore", elsewhere.toString(), "--keystore-password", "file:" + password,
                    "--tsa-url", url + "/tsa", "--ocsp-url", url + "/ocsp", "--crl-url", url + "/crl");

            assertEquals(0, run.exitCode(), run.toString());
            CAdESLtVerifier.Result result = new CAdESLtVerifier(unreachable.root().certificate()).verify(
                    new FileDocument(document + ".p7s"), new FileDocument(document.toFile()));
            assertEquals(SignatureLevel.CAdES_BASELINE_LT, result.level());
            assertEquals(Indication.TOTAL_PASSED, result.indication());
        } finally {
            own.server().stop(0);
        }
    }

    @Test
    @DisplayName("a revoked signer certificate is refused (3) and no signature is written")
    void revokedSigner() throws Exception {
        TestPki revokedPki = TestPki.create(dir.resolve("revoked.p12").toString(), "secret".toCharArray(),
                "http://127.0.0.1:9/crl", "http://127.0.0.1:9/ocsp");
        Services services = Services.start(revokedPki);
        services.ca().revoke(revokedPki.signer().certificate(), Instant.now().minusSeconds(3600));
        try {
            Cli.Run run = Cli.run("sign", document.toString(), "--strict",
                    "--keystore", dir.resolve("revoked.p12").toString(), "--keystore-password", "file:" + password,
                    "--tsa-url", services.url() + "/tsa",
                    "--ocsp-url", services.url() + "/ocsp", "--crl-url", services.url() + "/crl");

            assertEquals(3, run.exitCode(), run.toString());
            assertTrue(run.err().toLowerCase(java.util.Locale.ROOT).contains("revoked"), run.toString());
            assertFalse(Files.exists(Path.of(document + ".p7s")));
        } finally {
            services.server().stop(0);
        }
    }

    /** A TSA, OCSP responder and CRL distribution point for one test PKI. */
    private record Services(HttpServer server, String url, OfflineRevocation ca) {

        static Services start(TestPki pki) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            LocalTspSource tsa = new LocalTspSource(pki.tsa(), pki.root().certificate());
            OfflineRevocation ca = OfflineRevocation.forIssuers(List.of(pki.root()), tsa::lastIssuedAt);
            Map<BigInteger, X509Certificate> bySerial = Map.of(
                    pki.signer().certificate().getSerialNumber(), pki.signer().certificate(),
                    pki.tsa().certificate().getSerialNumber(), pki.tsa().certificate());
            server.createContext("/tsa", exchange -> respond(exchange, "application/timestamp-reply",
                    () -> tsa.processRequest(exchange.getRequestBody().readAllBytes())));
            server.createContext("/ocsp", exchange -> respond(exchange, "application/ocsp-response", () -> {
                OCSPReq request = new OCSPReq(exchange.getRequestBody().readAllBytes());
                BigInteger serial = request.getRequestList()[0].getCertID().getSerialNumber();
                return ca.ocspResponseFor(bySerial.get(serial)).orElseThrow();
            }));
            server.createContext("/crl", exchange -> respond(exchange, "application/pkix-crl",
                    () -> ca.crlFor(pki.signer().certificate()).orElseThrow()));
            server.start();
            return new Services(server, "http://127.0.0.1:" + server.getAddress().getPort(), ca);
        }
    }

    @Test
    @DisplayName("an unreachable TSA is an error (3) and leaves no signature behind")
    void unreachableTsa() {
        Cli.Run run = Cli.run("sign", document.toString(), "--strict",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password,
                "--tsa-url", "http://127.0.0.1:9/tsa");

        assertEquals(3, run.exitCode(), run.toString());
        assertFalse(Files.exists(Path.of(document + ".p7s")));
    }

    @Test
    @DisplayName("the online TSA alone reaches B-T, without --online-revocation")
    void onlineTsaReachesBt() {
        Cli.Run run = Cli.run("sign", document.toString(), "--level", "B-T",
                "--keystore", keystore.toString(), "--keystore-password", "file:" + password,
                "--tsa-url", baseUrl + "/tsa");

        assertEquals(0, run.exitCode(), run.toString());
        assertEquals(0, OCSP_REQUESTS.get() + CRL_REQUESTS.get());
    }

    private void assertLongTerm() {
        CAdESLtVerifier.Result result = new CAdESLtVerifier(pki.root().certificate()).verify(
                new FileDocument(document + ".p7s"), new FileDocument(document.toFile()));
        assertEquals(SignatureLevel.CAdES_BASELINE_LT, result.level());
        assertEquals(Indication.TOTAL_PASSED, result.indication());
    }

    @FunctionalInterface
    private interface Body {
        byte[] get() throws Exception;
    }

    private static void respond(HttpExchange exchange, String contentType, Body body) throws IOException {
        try (exchange) {
            byte[] bytes;
            try {
                bytes = body.get();
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
                return;
            }
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
    }
}
