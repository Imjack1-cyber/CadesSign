package com.example.cades;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.QcStatements;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;

import java.security.cert.X509Certificate;
import java.util.List;

/** Looks into a PKCS#11 token, to find the alias for {@code sign --pkcs11-key}. */
@Command(
        name = "pkcs11",
        description = "Inspect a PKCS#11 smartcard or HSM.",
        subcommands = Pkcs11Command.ListKeys.class)
class Pkcs11Command implements Runnable {

    @Override
    public void run() {
        picocli.CommandLine.usage(this, System.out);
    }

    @Command(
            name = "list",
            description = "List the signing keys on the token with their certificates. "
                    + "Slots are listed by pkcs11-tool --list-slots (OpenSC).")
    static class ListKeys implements Runnable {

        @Mixin
        Pkcs11Options pkcs11;

        @Override
        public void run() {
            if (!pkcs11.isSet()) {
                throw new IllegalArgumentException("--pkcs11-lib is required");
            }
            try (Pkcs11SignatureToken token = pkcs11.open()) {
                List<DSSPrivateKeyEntry> keys = token.getKeys();
                if (keys.isEmpty()) {
                    System.out.println("No private keys with a certificate on this token.");
                    return;
                }
                for (DSSPrivateKeyEntry entry : keys) {
                    print(entry);
                }
            }
        }

        private static void print(DSSPrivateKeyEntry entry) {
            X509Certificate certificate = entry.getCertificate().getCertificate();
            System.out.println("Key " + Pkcs11Options.alias(entry));
            System.out.println("  Subject    : " + certificate.getSubjectX500Principal().getName());
            System.out.println("  Issuer     : " + certificate.getIssuerX500Principal().getName());
            System.out.printf("  Valid      : %tF .. %tF%n",
                    certificate.getNotBefore(), certificate.getNotAfter());
            System.out.println("  Algorithm  : " + entry.getEncryptionAlgorithm());
            System.out.println("  Chain      : " + entry.getCertificateChain().length
                    + " certificate(s) on the token");
            QcStatements statements = CertificateExtensionsUtils.getQcStatements(
                    new CertificateToken(certificate));
            boolean qualified = statements != null && statements.isQcCompliance();
            System.out.println("  Qualified  : " + (qualified
                    ? "yes, QSCD " + (statements.isQcQSCD() ? "yes" : "no")
                    : "no"));
        }
    }
}
