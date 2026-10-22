package com.example.cades;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.Locale;

/**
 * Validates a signature against the original document and reports
 * the level actually achieved. The verifier is starved of any
 * external source, so only material embedded inside the signature
 * can make it pass.
 */
@picocli.CommandLine.Command(
        name = "verify",
        description = "Verify a CAdES signature against the "
                + "original document.")
class VerifyCommand implements Runnable {

    @Parameters(index = "0", arity = "0..1",
            description = "the original document "
                    + "(required for detached signatures, omitted for enveloped)")
    File input;

    @Parameters(index = "1", arity = "0..1",
            description = "the signature file (.p7s)")
    File signature;

    @Option(names = "--report", converter = ReportFormatConverter.class,
            description = "simple: compact summary (default); "
                    + "full: complete XML validation report")
    ReportFormat report = ReportFormat.SIMPLE;

    enum ReportFormat { SIMPLE, FULL }

    static final class ReportFormatConverter
            implements ITypeConverter<ReportFormat> {
        @Override
        public ReportFormat convert(String value) {
            try {
                return ReportFormat.valueOf(value.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "unknown report format: " + value + " (expected simple or full)");
            }
        }
    }

    @picocli.CommandLine.Mixin
    KeystoreOptions keystore;

    @Override
    public void run() {
        if (signature == null && input != null) {
            // A single positional argument is the signature of
            // a self-contained (enveloped) signature.
            signature = input;
            input = null;
        }
        if (signature == null) {
            throw new IllegalArgumentException("a signature file is required");
        }
        if (!signature.isFile()) {
            throw new IllegalArgumentException("signature file not found: " + signature);
        }
        if (input != null && !input.isFile()) {
            throw new IllegalArgumentException("document not found: " + input);
        }

        CAdESLtVerifier verifier = keystore.loadVerifier();
        DSSDocument signatureDocument = new FileDocument(signature);
        CAdESLtVerifier.Result result = input == null
                ? verifier.verify(signatureDocument)
                : verifier.verify(signatureDocument, new FileDocument(input));

        if (report == ReportFormat.FULL) {
            System.out.println(result.reports().getXmlValidationReport());
        } else {
            printSummary(result);
        }
    }

    /**
     * The signing self-check, judged against the level that was requested: it lists only the
     * properties that level promises (a timestamp from B-T, embedded validation data from B-LT,
     * an archive timestamp at B-LTA), so a B signature is not reported as a failed B-LT one.
     */
    static void printSelfCheck(CAdESLtVerifier.Result result, SignatureLevel requested) {
        int rank = rank(requested);
        System.out.println("Self-check:");
        System.out.println("  - Level requested    : " + requested);
        System.out.println("  - Level reached      : " + result.level());
        System.out.println("  - Signature intact?  : " + result.isSignatureIntact());
        System.out.println("  - Trusted chain?     : " + result.isChainTrusted());
        if (rank >= 1) {
            System.out.println("  - Timestamped?       : " + result.hasValidSignatureTimestamp());
        }
        if (rank >= 2) {
            System.out.println("  - Long-term?         : " + result.isLongTerm());
        }
        if (rank >= 3) {
            System.out.println("  - Archive timestamp? : " + result.hasValidArchiveTimestamp());
        }
        String note = rank >= 2
                ? result.indication().toString()
                // B and B-T embed no revocation data, so the offline validation cannot conclude.
                : "validation " + result.indication() + ", expected without embedded revocation data";
        System.out.println("  - Passed?            : " + result.isPassedFor(requested) + " (" + note + ")");
    }

    /** B = 0, B-T = 1, B-LT = 2, B-LTA = 3. */
    private static int rank(SignatureLevel level) {
        return switch (level) {
            case CAdES_BASELINE_T -> 1;
            case CAdES_BASELINE_LT -> 2;
            case CAdES_BASELINE_LTA -> 3;
            default -> 0;
        };
    }

    static void printSummary(CAdESLtVerifier.Result result) {
        System.out.println("Verification result:");
        System.out.println("  - Level reached : " + result.level());
        System.out.println("  - Passed?       : " + result.isPassed()
                + " (" + result.indication() + ")");
        System.out.println("  - Long-term?    : " + result.isLongTerm());
    }
}
