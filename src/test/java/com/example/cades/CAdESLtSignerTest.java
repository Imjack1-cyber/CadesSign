package com.example.cades;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLtSignerTest {

    private static final Path SAMPLES = Path.of("src/test/resources/samples");

    private static TestPki pki;
    private static CAdESLtSigner signer;
    private static CAdESLtVerifier verifier;

    @BeforeAll
    static void setUpPki() {
        pki = TestPki.generate();
        signer = new CAdESLtSigner(pki);
        verifier = new CAdESLtVerifier(pki.root().certificate());
    }

    @ParameterizedTest(name = "{0} is signed at CAdES-BASELINE-LT")
    @ValueSource(strings = {"config.xml", "invoice.xml", "measurements.xml"})
    @DisplayName("every sample XML reaches LT and validates")
    void signsSampleAtLongTermLevel(String fileName) {
        DSSDocument original = new FileDocument(SAMPLES.resolve(fileName).toFile());

        DSSDocument signature = signer.sign(original);
        CAdESLtVerifier.Result result = verifier.verify(signature, original);

        assertEquals(SignatureLevel.CAdES_BASELINE_LT, result.level(),
                "signature did not reach LT — most likely the timestamp or "
                        + "revocation data was not embedded");
        assertEquals(Indication.TOTAL_PASSED, result.indication());
    }

    @Test
    @DisplayName("detached signing leaves the original XML byte-identical")
    void leavesOriginalDocumentUntouched() throws Exception {
        Path source = SAMPLES.resolve("invoice.xml");
        byte[] before = Files.readAllBytes(source);

        signer.sign(new FileDocument(source.toFile()));

        assertArrayEquals(before, Files.readAllBytes(source));
    }

    @Test
    @DisplayName("a signature does not validate against modified content")
    void rejectsTamperedContent() {
        DSSDocument original = new FileDocument(SAMPLES.resolve("invoice.xml").toFile());
        DSSDocument signature = signer.sign(original);

        // Change the invoice total. Any single-byte change is enough; this
        // one is chosen because it is the kind of edit an attacker would
        // actually want to make.
        String tamperedXml = new String(readAll(original), StandardCharsets.UTF_8)
                .replace("<GrossTotal>2735.81</GrossTotal>",
                        "<GrossTotal>2.81</GrossTotal>");
        DSSDocument tampered = new InMemoryDocument(
                tamperedXml.getBytes(StandardCharsets.UTF_8));

        CAdESLtVerifier.Result result = verifier.verify(signature, tampered);

        assertNotEquals(Indication.TOTAL_PASSED, result.indication(),
                "a modified document must not validate against the original signature");
    }

    @Test
    @DisplayName("the same content signed twice produces distinct signatures")
    void producesDistinctSignaturesPerInvocation() {
        DSSDocument original = new FileDocument(SAMPLES.resolve("config.xml").toFile());

        byte[] first = readAll(signer.sign(original));
        byte[] second = readAll(signer.sign(original));

        assertFalse(Arrays.equals(first, second),
                "each signature embeds its own timestamp and revocation data, so "
                        + "two runs must never be byte-identical");
    }

    @Test
    @DisplayName("the TSA certificate carries a critical timeStamping EKU")
    void tsaCertificateIsRfc3161Compliant() throws Exception {
        X509Certificate tsaCertificate = pki.tsa().certificate();

        List<String> extendedKeyUsage = tsaCertificate.getExtendedKeyUsage();
        assertNotNull(extendedKeyUsage, "TSA certificate has no extended key usage");
        assertEquals(List.of(KeyPurposeId.id_kp_timeStamping.getId()), extendedKeyUsage,
                "RFC 3161 requires the EKU to contain only id-kp-timeStamping");
        assertTrue(tsaCertificate.getCriticalExtensionOIDs()
                        .contains(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage.getId()),
                "RFC 3161 requires the timeStamping EKU to be marked critical");
    }

    private static byte[] readAll(DSSDocument document) {
        try (var in = document.openStream()) {
            return in.readAllBytes();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to read document bytes", e);
        }
    }
}
