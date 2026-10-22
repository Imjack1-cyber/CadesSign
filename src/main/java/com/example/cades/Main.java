package com.example.cades;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * CLI entry point. Delegates to one of the subcommands
 * {@code sign}, {@code verify}, {@code gen-pki} or {@code tsa}.
 */
@Command(
        name = "cades-lt",
        mixinStandardHelpOptions = true,
        version = "cades-lt 1.0.0",
        description = "Offline CAdES (ETSI EN 319 122-1) demo "
                + "with a disposable test PKI and an in-process RFC 3161 TSA.",
        subcommands = {SignCommand.class, VerifyCommand.class,
                GenPkiCommand.class, TsaCommand.class})
public class Main implements Runnable {

    public static void main(String[] args) {
        CommandLine commandLine = new CommandLine(new Main());
        commandLine.setExecutionExceptionHandler((exception, cmd, parsedArgs) -> {
            System.err.println("Error: " + exception.getMessage());
            return 1;
        });
        System.exit(commandLine.execute(args));
    }

    @Override
    public void run() {
        CommandLine.usage(new Main(), System.out);
    }
}
