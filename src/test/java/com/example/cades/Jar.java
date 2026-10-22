package com.example.cades;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs the shaded jar in its own JVM, exactly as users do. Integration
 * tests only: failsafe runs after the package phase built the jar.
 */
final class Jar {

    static final Path PATH = Path.of("target", "cades-lt.jar");

    private Jar() {
    }

    static Cli.Run run(String... args) throws Exception {
        return run(Map.of(), args);
    }

    static Cli.Run run(Map<String, String> environment, String... args) throws Exception {
        assertTrue(Files.isRegularFile(PATH), PATH + " missing: run mvn verify, not mvn test");
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-jar");
        command.add(PATH.toAbsolutePath().toString());
        command.addAll(List.of(args));
        ProcessBuilder builder = new ProcessBuilder(command).redirectInput(new File("/dev/null"));
        builder.environment().putAll(environment);
        Process process = builder.start();
        CompletableFuture<String> err = CompletableFuture.supplyAsync(() -> read(process.getErrorStream()));
        String out = read(process.getInputStream());
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "timed out: " + command);
        return new Cli.Run(process.exitValue(), out, err.get());
    }

    private static String read(java.io.InputStream in) {
        try {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
