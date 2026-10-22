package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Selects where a signature's timestamp and revocation material
 * come from, plus the fixed signing parameters.
 *
 * <p>A {@code null} {@link #tspSource} means "in-process
 * {@link LocalTspSource}", and {@code null} revocation sources mean
 * "offline {@link OfflineRevocation} for the test PKI". This keeps
 * the default path entirely offline while letting the CLI substitute
 * online sources ({@code OnlineTSPSource}, {@code OnlineCRLSource},
 * {@code OnlineOCSPSource}) without touching the signing flow.
 *
 * @param digestAlgorithm          digest used for the signature value
 * @param signatureLevel           target baseline level
 * @param signaturePackaging       detached or enveloped
 * @param tspSource                timestamp source; {@code null} for
 *                                 the in-process TSA
 * @param signatureTimestampTime   supplies the timestamp's generation
 *                                 time so offline revocation material
 *                                 can be dated after it; {@code null}
 *                                 to derive it from an in-process TSA
 *                                 (or to fall back to the wall clock
 *                                 when an online TSA is in use)
 * @param crlSource                CRL source; {@code null} for offline
 * @param ocspSource               OCSP source; {@code null} for offline
 */
public record SigningConfig(
        DigestAlgorithm digestAlgorithm,
        SignatureLevel signatureLevel,
        SignaturePackaging signaturePackaging,
        TSPSource tspSource,
        Supplier<Optional<Instant>> signatureTimestampTime,
        RevocationSource<CRL> crlSource,
        RevocationSource<OCSP> ocspSource) {

    /** The offline defaults: SHA-256, CAdES B-LT, detached. */
    public static SigningConfig localDefaults() {
        return new SigningConfig(
                DigestAlgorithm.SHA256,
                SignatureLevel.CAdES_BASELINE_LT,
                SignaturePackaging.DETACHED,
                null,
                null,
                null,
                null);
    }
}
