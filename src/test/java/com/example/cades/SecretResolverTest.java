package com.example.cades;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretResolverTest {

    private final SecretResolver resolver =
            new SecretResolver(Map.of("CADES_PW", "from-env"), null);

    @TempDir
    Path dir;

    @Test
    @DisplayName("an option that was not given resolves to null")
    void absentOption() {
        assertNull(resolver.resolve("--pin", null));
    }

    @Test
    @DisplayName("env:VAR reads the environment variable")
    void environment() {
        assertArrayEquals("from-env".toCharArray(), resolver.resolve("--pin", "env:CADES_PW"));
    }

    @Test
    @DisplayName("a missing environment variable names the variable")
    void missingEnvironment() {
        var e = assertThrows(IllegalArgumentException.class,
                () -> resolver.resolve("--pin", "env:NOPE"));
        assertTrue(e.getMessage().contains("NOPE"), e.getMessage());
    }

    @Test
    @DisplayName("file:PATH reads the first line, without its line ending but with spaces")
    void file() throws Exception {
        Path secret = Files.writeString(dir.resolve("pw"), " with space \r\nsecond line\n");
        assertArrayEquals(" with space ".toCharArray(), resolver.resolve("--pin", "file:" + secret));
    }

    @Test
    @DisplayName("an unreadable file is reported with its path")
    void missingFile() {
        var e = assertThrows(IllegalArgumentException.class,
                () -> resolver.resolve("--pin", "file:" + dir.resolve("absent")));
        assertTrue(e.getMessage().contains("absent"), e.getMessage());
    }

    @Test
    @DisplayName("prompting without a console points to env: and file:")
    void promptWithoutConsole() {
        var e = assertThrows(IllegalArgumentException.class,
                () -> resolver.resolve("--pin", SecretResolver.PROMPT));
        assertTrue(e.getMessage().contains("env:VAR"), e.getMessage());
    }

    @Test
    @DisplayName("a literal value works but warns on stderr")
    void literalWarns() {
        PrintStream original = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            assertArrayEquals("plain".toCharArray(), resolver.resolve("--pin", "plain"));
        } finally {
            System.setErr(original);
        }
        String warning = captured.toString(StandardCharsets.UTF_8);
        assertTrue(warning.contains("--pin") && warning.contains("process list"), warning);
        assertEquals(1, warning.lines().count());
    }
}
