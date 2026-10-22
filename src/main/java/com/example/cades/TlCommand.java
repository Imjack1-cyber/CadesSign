package com.example.cades;

import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

import java.util.concurrent.Callable;

/** Keeps the EU trusted list cache that {@code verify --trust-lotl} reads. */
@Command(
        name = "tl",
        description = "Manage the EU trusted list cache used by verify --trust-lotl.",
        subcommands = {TlCommand.Refresh.class, TlCommand.Status.class})
class TlCommand implements Runnable {

    @Override
    public void run() {
        picocli.CommandLine.usage(this, System.out);
    }

    @Command(
            name = "refresh",
            description = "Download the LOTL and the national trusted lists into the cache "
                    + "and check their signatures. Run it daily, e.g. from cron.",
            exitCodeListHeading = "Exit codes:%n",
            exitCodeList = {
                    "0:the LOTL and at least one national list are valid",
                    "2:invalid options",
                    "3:the LOTL could not be downloaded or is not validly signed"})
    static class Refresh implements Callable<Integer> {

        @Mixin
        TrustedListOptions options;

        @Override
        public Integer call() {
            return report(options.trustedLists().refresh());
        }
    }

    @Command(
            name = "status",
            description = "Show the cached lists without network access.",
            exitCodeListHeading = "Exit codes:%n",
            exitCodeList = {
                    "0:the cache is fresh and the LOTL is valid",
                    "2:invalid options",
                    "3:the cache is missing, too old or holds no valid LOTL"})
    static class Status implements Callable<Integer> {

        @Mixin
        TrustedListOptions options;

        @Override
        public Integer call() {
            return report(options.trustedLists().load(options.maxAge()));
        }
    }

    private static int report(TrustedLists.Result result) {
        result.summary().getLOTLInfos().forEach(lotl -> {
            System.out.println(TrustedLists.describe(lotl));
            lotl.getTLInfos().forEach(tl -> System.out.println("  " + TrustedLists.describe(tl)));
        });
        System.out.println(result.validLists() + " of " + result.totalLists()
                + " lists valid, " + result.certificates().getNumberOfCertificates()
                + " trusted certificates");
        boolean lotlValid = result.summary().getLOTLInfos().stream().anyMatch(TrustedLists::isUsable);
        boolean anyTlValid = result.summary().getLOTLInfos().stream()
                .flatMap(lotl -> lotl.getTLInfos().stream())
                .anyMatch(TrustedLists::isUsable);
        if (!lotlValid || !anyTlValid) {
            System.err.println("Error: " + (lotlValid ? "no national list is valid"
                    : "the LOTL is not valid: check --lotl-keystore and the download"));
            return Main.EXIT_ERROR;
        }
        return 0;
    }
}
