package com.example.cades;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.model.DSSException;
import picocli.CommandLine.Option;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;

/** One-shot RFC 3161 timestamp server. */
@picocli.CommandLine.Command(
        name = "tsa",
        description = "Serve the in-process RFC 3161 TSA over "
                + "HTTP. Shuts down after --count tokens.")
class TsaCommand implements Runnable {

    @picocli.CommandLine.Mixin
    KeystoreOptions keystore;

    @Option(names = "--port",
            description = "HTTP port to listen on (default: ${DEFAULT-VALUE})")
    int port = 9999;

    @Option(names = "--count",
            description = "number of tokens to issue before shutting down "
                    + "(default: ${DEFAULT-VALUE})")
    int count = 1;

    @Override
    public void run() {
        if (count < 1) {
            throw new IllegalArgumentException("--count must be at least 1");
        }

        TestPki pki = keystore.loadPki();
        LocalTspSource tspSource = new LocalTspSource(pki.tsa(), pki.root().certificate());
        CountDownLatch tokensIssued = new CountDownLatch(count);

        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(port), 0);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(
                    "Unable to start the TSA server on port " + port, e);
        }
        server.createContext("/", exchange -> {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                byte[] request = exchange.getRequestBody().readAllBytes();
                byte[] response = tspSource.processRequest(request);
                exchange.getResponseHeaders().set(
                        "Content-Type", "application/timestamp-reply");
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream body = exchange.getResponseBody()) {
                    body.write(response);
                }
                tokensIssued.countDown();
                System.out.println("Issued token "
                        + (count - tokensIssued.getCount()) + " of " + count);
            } catch (DSSException e) {
                fail(exchange, e);
            } catch (Exception e) {
                fail(exchange, e);
            } finally {
                exchange.close();
            }
        });

        server.start();
        System.out.println("TSA listening on http://localhost:" + port
                + " — will shut down after " + count + " token(s)");

        try {
            tokensIssued.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            server.stop(0);
        }        System.out.println("Token target reached; TSA server stopped.");
    }

    private static void fail(HttpExchange exchange, Exception e) {
        System.err.println("TSA request failed: " + e.getMessage());
        try {
            exchange.sendResponseHeaders(500, -1);
        } catch (Exception ignored) {
            // the exchange may already be closed
        }
    }
}
