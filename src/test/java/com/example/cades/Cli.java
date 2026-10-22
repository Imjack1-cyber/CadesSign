package com.example.cades;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * Runs the CLI in-process exactly as {@link Main#main} does, minus
 * {@code System.exit}, and captures what it prints.
 */
final class Cli {

    private Cli() {
    }

    record Run(int exitCode, String out, String err) {
        @Override
        public String toString() {
            return "exit " + exitCode + "\n--- stdout\n" + out + "--- stderr\n" + err;
        }
    }

    static Run run(String... args) {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            int exitCode = Main.commandLine().execute(args);
            return new Run(exitCode, out.toString(StandardCharsets.UTF_8),
                    err.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }
}
