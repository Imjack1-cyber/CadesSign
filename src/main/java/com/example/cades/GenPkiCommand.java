package com.example.cades;

import picocli.CommandLine.Option;

import java.security.cert.X509Certificate;

/** Generates or loads the test PKI. */
@picocli.CommandLine.Command(
        name = "gen-pki",
        description = "Generate the test PKI into a PKCS#12 "
                + "keystore (or load it if it already exists).")
class GenPkiCommand implements Runnable {

    @picocli.CommandLine.Mixin
    KeystoreOptions keystore;

    @Override
    public void run() {
        TestPki pki = keystore.loadPki();
        System.out.println("Test PKI ready in " + keystore.keystorePath());
        printEntry("root ", pki.root());
        printEntry("signer", pki.signer());
        printEntry("tsa   ", pki.tsa());
    }

    private static void printEntry(String label, TestPki.CertificateAndKey entry) {
        X509Certificate certificate = entry.certificate();
        System.out.printf("  %s: %s (valid %tF .. %tF)%n",
                label,
                certificate.getSubjectX500Principal().getName(),
                certificate.getNotBefore(),
                certificate.getNotAfter());
    }
}
