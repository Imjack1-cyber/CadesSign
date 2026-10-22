package com.example.cades;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * Turns the value of a password or PIN option into the secret itself.
 *
 * <ul>
 *   <li>{@code env:NAME} reads the environment variable {@code NAME}</li>
 *   <li>{@code file:PATH} reads the first line of {@code PATH}</li>
 *   <li>the option without a value ({@link #PROMPT}) asks on the console</li>
 *   <li>anything else is the secret itself, with a warning, because
 *       command-line arguments show up in the process list and shell
 *       history</li>
 * </ul>
 */
final class SecretResolver {

    /** Fallback value picocli assigns when a secret option is given without a value. */
    static final String PROMPT = "prompt:";

    /** Option description suffix shared by every secret option. */
    static final String FORMS = "; use env:VAR, file:PATH, or give the option "
            + "without a value to be prompted";

    private final UnaryOperator<String> environment;
    private final Console console;

    SecretResolver() {
        this(System::getenv, System.console());
    }

    SecretResolver(Map<String, String> environment, Console console) {
        this(environment::get, console);
    }

    private SecretResolver(UnaryOperator<String> environment, Console console) {
        this.environment = environment;
        this.console = console;
    }

    /**
     * @param option the option name, for messages, e.g. {@code --keystore-password}
     * @param value  the option's raw value; {@code null} when the option was not given
     * @return the secret, or {@code null} when the option was not given
     */
    char[] resolve(String option, String value) {
        if (value == null) {
            return null;
        }
        if (value.equals(PROMPT)) {
            if (console == null) {
                throw new IllegalArgumentException(option + " without a value prompts for it, "
                        + "but there is no console; use " + option + " env:VAR or file:PATH");
            }
            char[] secret = console.readPassword("%s: ", option.replaceFirst("^--", ""));
            if (secret == null) {
                throw new IllegalArgumentException("no value entered for " + option);
            }
            return secret;
        }
        if (value.startsWith("env:")) {
            String name = value.substring("env:".length());
            String secret = environment.apply(name);
            if (secret == null) {
                throw new IllegalArgumentException(option + ": environment variable "
                        + name + " is not set");
            }
            return secret.toCharArray();
        }
        if (value.startsWith("file:")) {
            Path path = Path.of(value.substring("file:".length()));
            try {
                String content = Files.readString(path, StandardCharsets.UTF_8);
                int end = content.indexOf('\n');
                String line = end < 0 ? content : content.substring(0, end);
                // Only the line ending goes; spaces may be part of the secret.
                return line.replaceFirst("\r$", "").toCharArray();
            } catch (IOException e) {
                throw new IllegalArgumentException(option + ": cannot read " + path, e);
            }
        }
        System.err.println("Warning: " + option + " given on the command line is visible "
                + "to other users in the process list; use env:VAR or file:PATH instead.");
        return value.toCharArray();
    }
}
