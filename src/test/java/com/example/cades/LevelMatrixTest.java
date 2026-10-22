package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every level the CLI offers, in both packagings, with RSA and EC keys,
 * reaches exactly the level requested and passes the checks of that level.
 */
class LevelMatrixTest {

    @TempDir
    static Path dir;

    private static Map<String, TestPki> pkis;

    @BeforeAll
    static void createPkis() {
        pkis = Map.of(
                "RSA", TestPki.create(dir.resolve("rsa.p12").toString(), null,
                        "http://offline.invalid/demo.crl", "http://offline.invalid/ocsp", "RSA"),
                "EC", TestPki.create(dir.resolve("ec.p12").toString(), null,
                        "http://offline.invalid/demo.crl", "http://offline.invalid/ocsp", "EC"));
    }

    static Stream<Arguments> levelsAndPackagings() {
        List<Arguments> cases = new ArrayList<>();
        for (String key : List.of("RSA", "EC")) {
            for (SignatureLevel level : List.of(SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                    SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA)) {
                for (SignaturePackaging packaging : List.of(SignaturePackaging.DETACHED,
                        SignaturePackaging.ENVELOPING)) {
                    cases.add(Arguments.of(key, level, packaging, DigestAlgorithm.SHA256));
                }
            }
            for (DigestAlgorithm digest : List.of(DigestAlgorithm.SHA384, DigestAlgorithm.SHA512)) {
                cases.add(Arguments.of(key, SignatureLevel.CAdES_BASELINE_LT, SignaturePackaging.DETACHED, digest));
            }
        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{0} {1} {2} {3}")
    @MethodSource("levelsAndPackagings")
    void reachesRequestedLevel(String key, SignatureLevel level, SignaturePackaging packaging,
                               DigestAlgorithm digest) {
        TestPki pki = pkis.get(key);
        DSSDocument original = new InMemoryDocument(
                "<invoice>42</invoice>".getBytes(StandardCharsets.UTF_8), "invoice.xml");

        DSSDocument signature = new CAdESLtSigner(pki.toCredentials(),
                new SigningConfig(digest, level, packaging, null, null, null, null)).sign(original);

        CAdESLtVerifier verifier = new CAdESLtVerifier(pki.root().certificate());
        CAdESLtVerifier.Result result = packaging == SignaturePackaging.DETACHED
                ? verifier.verify(signature, original)
                : verifier.verify(signature);
        assertEquals(level, result.level());
        assertTrue(result.isPassedFor(level), () -> "not passed: " + result.indication());
        assertTrue(result.isSignatureIntact());
    }
}
