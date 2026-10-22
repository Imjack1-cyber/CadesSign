package com.example.cades;

import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

/**
 * The EU List of Trusted Lists (LOTL) and the national trusted lists it
 * points to, as a source of trust anchors for verification.
 *
 * <p>Downloads go to a file cache, so {@code verify --trust-lotl} works
 * offline once {@code cades tl refresh} has run. A list is trusted only if
 * its signature verifies and it has not expired: the LOTL against the
 * signing certificates announced in the Official Journal, each national
 * list against the certificates the LOTL names for it.
 */
final class TrustedLists {

    static final String EU_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

    /** Where the EU announces the LOTL signing certificates. */
    static final String EU_OJ_URL =
            "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG";

    private final Path cacheDirectory;
    private final String lotlUrl;
    private final String officialJournalUrl;
    private final CertificateSource lotlSigners;
    private final DataLoader dataLoader;

    /**
     * @param cacheDirectory     where downloaded lists are kept
     * @param lotlUrl            the LOTL to start from
     * @param officialJournalUrl the publication announcing the LOTL signers,
     *                           or {@code null} to trust {@code lotlSigners} only
     * @param lotlSigners        certificates allowed to sign the LOTL
     * @param dataLoader         downloads the lists
     */
    TrustedLists(Path cacheDirectory, String lotlUrl, String officialJournalUrl,
                 CertificateSource lotlSigners, DataLoader dataLoader) {
        this.cacheDirectory = cacheDirectory;
        this.lotlUrl = lotlUrl;
        this.officialJournalUrl = officialJournalUrl;
        this.lotlSigners = lotlSigners;
        this.dataLoader = dataLoader;
    }

    TrustedLists(Path cacheDirectory, String lotlUrl, String officialJournalUrl,
                 CertificateSource lotlSigners) {
        this(cacheDirectory, lotlUrl, officialJournalUrl, lotlSigners, new CommonsDataLoader());
    }

    /** {@code ~/.cache/cades/tl}, or below {@code XDG_CACHE_HOME}. */
    static Path defaultCacheDirectory() {
        String xdg = System.getenv("XDG_CACHE_HOME");
        Path base = xdg != null && !xdg.isBlank()
                ? Path.of(xdg)
                : Path.of(System.getProperty("user.home"), ".cache");
        return base.resolve("cades").resolve("tl");
    }

    /** Downloads the LOTL and every national list into the cache. */
    Result refresh() {
        try {
            Files.createDirectories(cacheDirectory);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create the trusted list cache " + cacheDirectory, e);
        }
        TrustedListsCertificateSource source = new TrustedListsCertificateSource();
        TLValidationJob job = job(source);
        job.onlineRefresh();
        return new Result(source, job.getSummary());
    }

    /**
     * Loads the lists from the cache, without network access.
     *
     * @param maxAge how old the cache may be; {@code null} for any age
     */
    Result load(Duration maxAge) {
        Instant newest = newestCacheEntry();
        if (newest == null) {
            throw new IllegalStateException("The trusted list cache " + cacheDirectory
                    + " is empty: run cades tl refresh first");
        }
        if (maxAge != null && newest.isBefore(Instant.now().minus(maxAge))) {
            throw new IllegalStateException("The trusted list cache " + cacheDirectory
                    + " was last refreshed " + newest + ", longer ago than " + maxAge
                    + ": run cades tl refresh");
        }
        TrustedListsCertificateSource source = new TrustedListsCertificateSource();
        TLValidationJob job = job(source);
        job.offlineRefresh();
        return new Result(source, job.getSummary());
    }

    private TLValidationJob job(TrustedListsCertificateSource source) {
        TLValidationJob job = new TLValidationJob();
        job.setOnlineDataLoader(onlineLoader());
        job.setOfflineDataLoader(offlineLoader());
        job.setTrustedListCertificateSource(source);
        // Unlike AcceptAllStrategy, lists that are expired or whose
        // signature does not verify contribute no trust anchors.
        job.setSynchronizationStrategy(new ExpirationAndSignatureCheckStrategy());
        job.setListOfTrustedListSources(lotlSource());
        return job;
    }

    private LOTLSource lotlSource() {
        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(lotlUrl);
        lotl.setCertificateSource(lotlSigners);
        if (officialJournalUrl != null) {
            lotl.setSigningCertificatesAnnouncementPredicate(
                    new OfficialJournalSchemeInformationURI(officialJournalUrl));
        }
        lotl.setPivotSupport(true);
        return lotl;
    }

    private DSSFileLoader onlineLoader() {
        FileCacheDataLoader loader = new FileCacheDataLoader();
        loader.setCacheExpirationTime(0);
        loader.setDataLoader(dataLoader);
        loader.setFileCacheDirectory(cacheDirectory.toFile());
        return loader;
    }

    private DSSFileLoader offlineLoader() {
        FileCacheDataLoader loader = new FileCacheDataLoader();
        loader.setCacheExpirationTime(-1);
        loader.setDataLoader(new IgnoreDataLoader());
        loader.setFileCacheDirectory(cacheDirectory.toFile());
        return loader;
    }

    private Instant newestCacheEntry() {
        if (!Files.isDirectory(cacheDirectory)) {
            return null;
        }
        try (Stream<Path> files = Files.list(cacheDirectory)) {
            return files.map(Path::toFile)
                    .filter(File::isFile)
                    .map(file -> Instant.ofEpochMilli(file.lastModified()))
                    .max(Instant::compareTo)
                    .orElse(null);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read the trusted list cache " + cacheDirectory, e);
        }
    }

    /**
     * @param certificates the trust anchors of every valid list
     * @param summary      DSS's account of each list: downloaded, parsed, signature valid
     */
    record Result(TrustedListsCertificateSource certificates, TLValidationJobSummary summary) {

        int validLists() {
            return (int) lists().filter(TrustedLists::isUsable).count();
        }

        int totalLists() {
            return (int) lists().count();
        }

        private Stream<TLInfo> lists() {
            return summary.getLOTLInfos().stream()
                    .flatMap(lotl -> Stream.concat(Stream.of(lotl), lotl.getTLInfos().stream()));
        }
    }

    /** Parsed, signed by a trusted certificate, and not expired. */
    static boolean isUsable(TLInfo info) {
        var validation = info.getValidationCacheInfo();
        var parsing = info.getParsingCacheInfo();
        return validation != null && validation.isValid()
                && parsing != null && parsing.getNextUpdateDate() != null
                && parsing.getNextUpdateDate().toInstant().isAfter(Instant.now());
    }

    static String describe(TLInfo info) {
        var parsing = info.getParsingCacheInfo();
        String territory = parsing == null || parsing.getTerritory() == null ? "?" : parsing.getTerritory();
        String kind = info instanceof LOTLInfo ? "LOTL" : "TL";
        return kind + " " + territory + " " + (isUsable(info) ? "valid" : "NOT USED") + " (" + info.getUrl() + ")";
    }
}
