package com.example.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A miniature EU trust infrastructure: a LOTL signed by a "Commission" key,
 * pointing to one national trusted list signed by a "supervisory body" key,
 * which lists a qualified CA. Everything is served from memory, so the
 * whole path runs offline: download, signature checks, cache, and the
 * qualification of a signature made with that CA's certificate.
 */
class TrustedListsIT {

    private static final String LOTL_URL = "http://lotl.test/eu-lotl.xml";
    private static final String TL_URL = "http://lotl.test/tl-de.xml";
    private static final char[] PASSWORD = "secret".toCharArray();

    @TempDir
    static Path dir;

    private static TestPki commission;
    private static TestPki supervisor;
    private static TestPki qualifiedCa;
    private static Path lotlSigners;
    private static Path document;
    private static Path signature;
    private static Path password;

    @BeforeAll
    static void buildTrustInfrastructure() throws Exception {
        commission = TestPki.create(dir.resolve("commission.p12").toString(), PASSWORD);
        supervisor = TestPki.create(dir.resolve("supervisor.p12").toString(), PASSWORD);
        qualifiedCa = TestPki.create(dir.resolve("qca.p12").toString(), PASSWORD);

        lotlSigners = dir.resolve("lotl-signers.pem");
        Files.writeString(lotlSigners, pem(commission.signer().certificate()));
        password = Files.writeString(dir.resolve("password"), "secret\n");

        // A qualified signature: QC statements, key on a QSCD, LT.
        TestPki.CertificateAndKey signer = TestCertificates.qualifiedSigner(qualifiedCa, true);
        Path signerFile = pkcs12(dir.resolve("signer.p12"), signer, qualifiedCa.root());
        Path tsaFile = pkcs12(dir.resolve("tsa.p12"), qualifiedCa.tsa(), qualifiedCa.root());
        document = Files.writeString(dir.resolve("contract.txt"), "signed under eIDAS");
        signature = dir.resolve("contract.txt.p7s");
        Cli.Run signed = Cli.run("sign", document.toString(), "-o", signature.toString(),
                "--signer", signerFile.toString(), "--signer-password", "file:" + password,
                "--tsa", tsaFile.toString(), "--tsa-password", "file:" + password);
        assertEquals(0, signed.exitCode(), signed.toString());
    }

    private static TrustedLists lists(Path cache, byte[] lotl, byte[] tl) {
        Map<String, byte[]> content = new HashMap<>();
        content.put(LOTL_URL, lotl);
        content.put(TL_URL, tl);
        CommonCertificateSource signers = new CommonCertificateSource();
        signers.addCertificate(new CertificateToken(commission.signer().certificate()));
        return new TrustedLists(cache, LOTL_URL, null, signers, new MemoryDataLoader(content));
    }

    private static Path freshCache(String name, byte[] tl) throws Exception {
        Path cache = dir.resolve(name);
        TrustedLists.Result result = lists(cache, lotl(), tl).refresh();
        assertTrue(result.totalLists() >= 2, "LOTL and TL should both be loaded");
        return cache;
    }

    @Test
    @DisplayName("a refreshed cache trusts the listed CA and makes the signature QESig")
    void qualifiedSignature() throws Exception {
        Path cache = freshCache("cache-ok", nationalList(supervisor.signer()));

        Cli.Run status = Cli.run(tlArgs("tl", "status", cache));
        assertEquals(0, status.exitCode(), status.toString());
        assertTrue(status.out().contains("2 of 2 lists valid"), status.toString());

        Cli.Run run = Cli.run(verifyArgs(cache, "--report", "json"));
        assertEquals(0, run.exitCode(), run.toString());
        assertTrue(run.out().contains("\"chainTrusted\":true"), run.toString());
        assertTrue(run.out().contains("\"qualification\":\"QESig\""), run.toString());

        Cli.Run summary = Cli.run(verifyArgs(cache));
        assertTrue(summary.out().contains("Qualification : QESig"), summary.toString());
    }

    @Test
    @DisplayName("a national list not signed by the key the LOTL names is not used")
    void wronglySignedList() throws Exception {
        // Signed by the qualified CA's own key instead of the supervisor's.
        Path cache = freshCache("cache-bad-tl", nationalList(qualifiedCa.signer()));

        Cli.Run status = Cli.run(tlArgs("tl", "status", cache));
        assertEquals(3, status.exitCode(), status.toString());
        assertTrue(status.err().contains("no national list is valid"), status.toString());

        Cli.Run run = Cli.run(verifyArgs(cache));
        assertEquals(1, run.exitCode(), run.toString());
    }

    @Test
    @DisplayName("a cache older than --tl-max-age is refused")
    void staleCache() throws Exception {
        Path cache = freshCache("cache-stale", nationalList(supervisor.signer()));
        FileTime old = FileTime.from(Instant.now().minus(30, ChronoUnit.DAYS));
        try (Stream<Path> files = Files.list(cache)) {
            for (Path file : files.toList()) {
                Files.setLastModifiedTime(file, old);
            }
        }

        Cli.Run run = Cli.run(verifyArgs(cache, "--tl-max-age", "14"));
        assertEquals(3, run.exitCode(), run.toString());
        assertTrue(run.err().contains("tl refresh"), run.toString());

        Cli.Run anyAge = Cli.run(verifyArgs(cache, "--tl-max-age", "0"));
        assertEquals(0, anyAge.exitCode(), anyAge.toString());
    }

    @Test
    @DisplayName("an empty cache asks for tl refresh; a missing --lotl-keystore is a usage error")
    void missingCacheOrKeystore() {
        Cli.Run empty = Cli.run(verifyArgs(dir.resolve("no-cache")));
        assertEquals(3, empty.exitCode(), empty.toString());
        assertTrue(empty.err().contains("run cades tl refresh first"), empty.toString());

        Cli.Run noKeystore = Cli.run("verify", document.toString(), signature.toString(), "--trust-lotl");
        assertEquals(2, noKeystore.exitCode(), noKeystore.toString());
        assertTrue(noKeystore.err().contains("--lotl-keystore"), noKeystore.toString());
    }

    @Test
    @DisplayName("the packaged jar refreshes the lists over HTTP and finds the signature qualified")
    void packagedJarOverHttp() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        byte[] lotl = lotl(base + "/tl-de.xml");
        byte[] tl = nationalList(supervisor.signer());
        server.createContext("/eu-lotl.xml", exchange -> serve(exchange, lotl));
        server.createContext("/tl-de.xml", exchange -> serve(exchange, tl));
        server.start();
        try {
            Path cache = dir.resolve("cache-jar");
            String[] options = {"--tl-cache", cache.toString(), "--lotl-url", base + "/eu-lotl.xml",
                    "--lotl-oj-url", "none", "--lotl-keystore", lotlSigners.toString()};

            Cli.Run refresh = Jar.run(concat(new String[]{"tl", "refresh"}, options));
            assertEquals(0, refresh.exitCode(), refresh.toString());
            assertTrue(refresh.out().contains("2 of 2 lists valid"), refresh.toString());

            Cli.Run verify = Jar.run(concat(new String[]{"verify", document.toString(), signature.toString(),
                    "--trust-lotl"}, options));
            assertEquals(0, verify.exitCode(), verify.toString());
            assertTrue(verify.out().contains("Qualification : QESig"), verify.toString());
        } finally {
            server.stop(0);
        }
    }

    private static void serve(HttpExchange exchange, byte[] body) throws java.io.IOException {
        try (exchange) {
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
        }
    }

    private static String[] concat(String[] first, String[] second) {
        return Stream.concat(Stream.of(first), Stream.of(second)).toArray(String[]::new);
    }

    private static String[] verifyArgs(Path cache, String... extra) {
        List<String> args = new java.util.ArrayList<>(List.of("verify", document.toString(),
                signature.toString(), "--trust-lotl"));
        args.addAll(List.of(tlOptions(cache)));
        args.addAll(List.of(extra));
        return args.toArray(String[]::new);
    }

    private static String[] tlArgs(String command, String sub, Path cache) {
        List<String> args = new java.util.ArrayList<>(List.of(command, sub));
        args.addAll(List.of(tlOptions(cache)));
        return args.toArray(String[]::new);
    }

    private static String[] tlOptions(Path cache) {
        return new String[]{"--tl-cache", cache.toString(), "--lotl-url", LOTL_URL,
                "--lotl-oj-url", "none", "--lotl-keystore", lotlSigners.toString()};
    }

    // --- the lists themselves -------------------------------------------------

    private static byte[] lotl() throws Exception {
        return lotl(TL_URL);
    }

    private static byte[] lotl(String tlUrl) throws Exception {
        String pointer = """
                <tsl:OtherTSLPointer>
                  <tsl:ServiceDigitalIdentities>
                    <tsl:ServiceDigitalIdentity>
                      <tsl:DigitalId><tsl:X509Certificate>%s</tsl:X509Certificate></tsl:DigitalId>
                    </tsl:ServiceDigitalIdentity>
                  </tsl:ServiceDigitalIdentities>
                  <tsl:TSLLocation>%s</tsl:TSLLocation>
                  <tsl:AdditionalInformation>
                    <tsl:OtherInformation><tsl:TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</tsl:TSLType></tsl:OtherInformation>
                    <tsl:OtherInformation><tsl:SchemeOperatorName><tsl:Name xml:lang="en">Supervisory Body</tsl:Name></tsl:SchemeOperatorName></tsl:OtherInformation>
                    <tsl:OtherInformation><tsl:SchemeTypeCommunityRules><tsl:URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon</tsl:URI></tsl:SchemeTypeCommunityRules></tsl:OtherInformation>
                    <tsl:OtherInformation><tsl:SchemeTerritory>DE</tsl:SchemeTerritory></tsl:OtherInformation>
                    <tsl:OtherInformation><tslx:MimeType xmlns:tslx="http://uri.etsi.org/02231/v2/additionaltypes#">application/vnd.etsi.tsl+xml</tslx:MimeType></tsl:OtherInformation>
                  </tsl:AdditionalInformation>
                </tsl:OtherTSLPointer>
                """.formatted(base64(supervisor.signer().certificate()), tlUrl);
        String xml = list("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists", "EU",
                "<tsl:PointersToOtherTSL>" + pointer + "</tsl:PointersToOtherTSL>", "");
        return signXml(xml, commission.signer());
    }

    private static byte[] nationalList(TestPki.CertificateAndKey signer) throws Exception {
        String provider = """
                <tsl:TrustServiceProviderList>
                  <tsl:TrustServiceProvider>
                    <tsl:TSPInformation>
                      <tsl:TSPName><tsl:Name xml:lang="en">Test QTSP</tsl:Name></tsl:TSPName>
                      <tsl:TSPAddress>
                        <tsl:PostalAddresses><tsl:PostalAddress xml:lang="en">
                          <tsl:StreetAddress>Street 1</tsl:StreetAddress><tsl:Locality>Berlin</tsl:Locality>
                          <tsl:CountryName>DE</tsl:CountryName>
                        </tsl:PostalAddress></tsl:PostalAddresses>
                        <tsl:ElectronicAddress><tsl:URI xml:lang="en">https://qtsp.test</tsl:URI></tsl:ElectronicAddress>
                      </tsl:TSPAddress>
                      <tsl:TSPInformationURI><tsl:URI xml:lang="en">https://qtsp.test</tsl:URI></tsl:TSPInformationURI>
                    </tsl:TSPInformation>
                    <tsl:TSPServices>
                      <tsl:TSPService>
                        <tsl:ServiceInformation>
                          <tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>
                          <tsl:ServiceName><tsl:Name xml:lang="en">Test Qualified CA</tsl:Name></tsl:ServiceName>
                          <tsl:ServiceDigitalIdentity>
                            <tsl:DigitalId><tsl:X509Certificate>%s</tsl:X509Certificate></tsl:DigitalId>
                          </tsl:ServiceDigitalIdentity>
                          <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>
                          <tsl:StatusStartingTime>2020-01-01T00:00:00Z</tsl:StatusStartingTime>
                          <tsl:ServiceInformationExtensions>
                            <tsl:Extension Critical="false">
                              <tsl:AdditionalServiceInformation>
                                <tsl:URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures</tsl:URI>
                              </tsl:AdditionalServiceInformation>
                            </tsl:Extension>
                          </tsl:ServiceInformationExtensions>
                        </tsl:ServiceInformation>
                      </tsl:TSPService>
                    </tsl:TSPServices>
                  </tsl:TrustServiceProvider>
                </tsl:TrustServiceProviderList>
                """.formatted(base64(qualifiedCa.root().certificate()));
        String xml = list("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", "DE", "", provider);
        return signXml(xml, signer);
    }

    private static String list(String type, String territory, String pointers, String providers) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/19612/TSLTag">
                  <tsl:SchemeInformation>
                    <tsl:TSLVersionIdentifier>5</tsl:TSLVersionIdentifier>
                    <tsl:TSLSequenceNumber>1</tsl:TSLSequenceNumber>
                    <tsl:TSLType>%s</tsl:TSLType>
                    <tsl:SchemeOperatorName><tsl:Name xml:lang="en">Test Operator</tsl:Name></tsl:SchemeOperatorName>
                    <tsl:SchemeOperatorAddress>
                      <tsl:PostalAddresses><tsl:PostalAddress xml:lang="en">
                        <tsl:StreetAddress>Street 1</tsl:StreetAddress><tsl:Locality>Brussels</tsl:Locality>
                        <tsl:CountryName>%s</tsl:CountryName>
                      </tsl:PostalAddress></tsl:PostalAddresses>
                      <tsl:ElectronicAddress><tsl:URI xml:lang="en">https://operator.test</tsl:URI></tsl:ElectronicAddress>
                    </tsl:SchemeOperatorAddress>
                    <tsl:SchemeName><tsl:Name xml:lang="en">Test Scheme</tsl:Name></tsl:SchemeName>
                    <tsl:SchemeInformationURI><tsl:URI xml:lang="en">https://operator.test/scheme</tsl:URI></tsl:SchemeInformationURI>
                    <tsl:StatusDeterminationApproach>http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate</tsl:StatusDeterminationApproach>
                    <tsl:SchemeTypeCommunityRules><tsl:URI xml:lang="en">http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon</tsl:URI></tsl:SchemeTypeCommunityRules>
                    <tsl:SchemeTerritory>%s</tsl:SchemeTerritory>
                    <tsl:PolicyOrLegalNotice><tsl:TSLLegalNotice xml:lang="en">Test only</tsl:TSLLegalNotice></tsl:PolicyOrLegalNotice>
                    <tsl:HistoricalInformationPeriod>65535</tsl:HistoricalInformationPeriod>
                    %s
                    <tsl:ListIssueDateTime>%s</tsl:ListIssueDateTime>
                    <tsl:NextUpdate><tsl:dateTime>%s</tsl:dateTime></tsl:NextUpdate>
                  </tsl:SchemeInformation>
                  %s
                </tsl:TrustServiceStatusList>
                """.formatted(type, territory, territory, pointers,
                now.minus(1, ChronoUnit.DAYS), now.plus(90, ChronoUnit.DAYS), providers);
    }

    /** Enveloped XAdES-B over the whole list, as ETSI TS 119 612 requires. */
    private static byte[] signXml(String xml, TestPki.CertificateAndKey signer) throws Exception {
        DSSDocument document = new InMemoryDocument(xml.getBytes(StandardCharsets.UTF_8), "tl.xml");

        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setEn319132(false);
        parameters.setSigningCertificate(new CertificateToken(signer.certificate()));

        DSSReference reference = new DSSReference();
        reference.setId("xml_ref_id");
        reference.setUri("");
        reference.setContents(document);
        reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
        reference.setTransforms(List.<DSSTransform>of(new EnvelopedSignatureTransform(),
                new CanonicalizationTransform("http://www.w3.org/2001/10/xml-exc-c14n#")));
        parameters.setReferences(List.of(reference));

        XAdESService service = new XAdESService(new CommonCertificateVerifier());
        ToBeSigned toBeSigned = service.getDataToSign(document, parameters);
        SignatureValue value = SigningKey.software(signer).sign(toBeSigned, DigestAlgorithm.SHA256);
        DSSDocument signed = service.signDocument(document, parameters, value);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        signed.writeTo(out);
        return out.toByteArray();
    }

    private static String base64(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private static String pem(X509Certificate certificate) throws Exception {
        StringWriter text = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
            writer.writeObject(certificate);
        }
        return text.toString();
    }

    private static Path pkcs12(Path target, TestPki.CertificateAndKey... entries) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        for (int i = 0; i < entries.length; i++) {
            keyStore.setKeyEntry(i == 0 ? "key" : "ca" + i, entries[i].privateKey(), PASSWORD,
                    new Certificate[]{entries[i].certificate()});
        }
        try (FileOutputStream out = new FileOutputStream(target.toFile())) {
            keyStore.store(out, PASSWORD);
        }
        return target;
    }
}
