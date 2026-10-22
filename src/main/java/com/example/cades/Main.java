package com.example.cades;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ScopeType;

import java.io.InputStream;
import java.util.Properties;

/**
 * CLI entry point. Delegates to one of the subcommands
 * {@code sign}, {@code verify}, {@code gen-pki}, {@code tsa}, {@code pkcs11} or {@code tl}.
 */
@Command(
        name = "cades",
        mixinStandardHelpOptions = true,
        // Every subcommand gets --help and --version too.
        scope = ScopeType.INHERIT,
        versionProvider = Main.Version.class,
        description = "Create and verify CAdES Baseline signatures (ETSI EN 319 122-1) "
                + "up to B-LTA.",
        subcommands = {SignCommand.class, VerifyCommand.class,
                GenPkiCommand.class, TsaCommand.class, Pkcs11Command.class,
                TlCommand.class})
public class Main implements Runnable {

    /** Invalid options or arguments, as picocli reports its own parse errors. */
    static final int EXIT_USAGE = CommandLine.ExitCode.USAGE;

    /** Keys, files or services that exist but could not be used. */
    static final int EXIT_ERROR = 3;

    private static boolean verbose;

    @Option(names = {"-v", "--verbose"}, scope = ScopeType.INHERIT,
            description = "log DSS progress (INFO) and print stack traces on errors")
    void setVerbose(boolean value) {
        verbose = value;
        if (value) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
        }
    }

    @Option(names = {"-q", "--quiet"}, scope = ScopeType.INHERIT,
            description = "log errors only")
    void setQuiet(boolean value) {
        if (value) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        }
    }

    public static void main(String[] args) {
        System.exit(commandLine().execute(args));
    }

    /** The configured command line, shared with the tests. */
    static CommandLine commandLine() {
        CommandLine commandLine = new CommandLine(new Main());
        commandLine.setExecutionExceptionHandler((exception, cmd, parsedArgs) -> {
            System.err.println("Error: " + message(exception));
            if (verbose) {
                exception.printStackTrace();
            }
            return exitCode(exception);
        });
        return commandLine;
    }

    /**
     * An {@link IllegalArgumentException} of our own, without a cause, is a
     * problem with the options or arguments; anything that failed while
     * reading keys, files or talking to a service is an error.
     */
    static int exitCode(Exception exception) {
        return exception instanceof IllegalArgumentException && exception.getCause() == null
                ? EXIT_USAGE
                : EXIT_ERROR;
    }

    /** The message, followed by the innermost cause's when that adds something. */
    static String message(Throwable exception) {
        Throwable root = exception;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String message = String.valueOf(exception.getMessage());
        if (root != exception && root.getMessage() != null
                && !message.contains(root.getMessage())) {
            message += ": " + root.getMessage();
        }
        return message;
    }

    @Override
    public void run() {
        CommandLine.usage(new Main(), System.out);
    }

    /** Version of the CLI and of the libraries that do the actual work. */
    static final class Version implements CommandLine.IVersionProvider {
        @Override
        public String[] getVersion() throws Exception {
            Properties properties = new Properties();
            try (InputStream in = Main.class.getResourceAsStream("/cades-version.properties")) {
                if (in != null) {
                    properties.load(in);
                }
            }
            return new String[]{
                    "cades " + properties.getProperty("version", "unknown"),
                    "DSS " + properties.getProperty("dss", "unknown")
                            + ", BouncyCastle " + properties.getProperty("bouncycastle", "unknown"),
                    "Java " + System.getProperty("java.version")
                            + " (" + System.getProperty("java.vendor") + ")"};
        }
    }
}
