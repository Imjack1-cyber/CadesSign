package cades.de;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.net.URL;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cades.de.exception.ApplicationException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.FileCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.Marshaller;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "cades-sign", version = "CadesSign 1.0", description = "CadesSign - A tool for signing files using CAdES signatures.", mixinStandardHelpOptions = true)
public class CadesSign implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(CadesSign.class);

    // Common options
    @Option(names = { "-i",
            "--input" }, description = "Path to the input file to be signed or verified.", required = true)
    private File inputFile;

    @Option(names = { "-ll",
            "--logLevel" }, description = "Logging level for Log4j2 (e.g., TRACE, DEBUG, INFO, WARN, ERROR, FATAL). Default: INFO", defaultValue = "INFO")
    private String logLevel;

    @Option(names = { "-o",
            "--output" }, description = "Path to the output file where the signed data will be saved. If not specified, the signed file will be saved in the same directory as the input file with a default name based on the input file name and signature level. Optional.")
    private String outputFile;

    @Option(names = { "-op",
            "--outputPath" }, description = "Path to the output directory where the signed file will be saved. If specified, the signed file will be saved in this directory with a default name based on the input file name and signature level. Optional.")
    private String outputPath;

    // Signing options
    @Option(names = { "-s",
            "--sign" }, description = "Sign the input file using CAdES signature with the specified parameters.", defaultValue = "false")
    private boolean sign;

    @Option(names = { "-c",
            "--cert" }, description = "Path to the pkcs12 file including the certificate and private key (e.g., .p12, .pfx) used for signing. Required if the Option -s or --sign is used.")
    private File certFile;

    @Option(names = { "-p",
            "--password" }, description = "Password for the pkcs12 file. Required if the Option -s or --sign is used.")
    private String certPassword;

    @Option(names = { "-l",
            "--signatureLevel" }, description = "CAdES signature level (e.g., CAdES_BASELINE_B, CAdES_BASELINE_T, CAdES_BASELINE_LT).")
    private SignatureLevel signatureLevel;

    @Option(names = { "-P",
            "--packaging" }, description = "Signature packaging type (ENVELOPING, DETACHED). Default: ENVELOPING", defaultValue = "ENVELOPING")
    private SignaturePackaging signaturePackaging;

    @Option(names = { "-a",
            "--algorithm" }, description = "Signature algorithm (e.g., RSA_SHA256, ECDSA_SHA256). Default: RSA_SHA256", defaultValue = "RSA_SHA256")
    private SignatureAlgorithm signatureAlgorithm;

    @Option(names = { "-t",
            "--tsaUrl" }, description = "URL of the Time Stamping Authority (TSA) to include a timestamp in the signature. Required, if signature level is higher than CAdES-BASELINE-B")
    private String tsaUrl;

    @Option(names = { "-ta",
            "--trustAnchorAlias" }, description = "Alias of the certificate from the PKCS12 file to be used as the trusted anchor. If not specified, all certificates in the trust chain will be listed for selection. Optional for signing.")
    private String trustAnchorAlias;

    @Option(names = { "-iCrl",
            "--intermediateCrlUrl" }, description = "URL of the intermediate CRL (Certificate Revocation List) to check the revocation status of the signing certificate.")
    private String intermediateCrlSourceUrl;

    @Option(names = { "-rCrl",
            "--rootCrlUrl" }, description = "URL of the root CRL (Certificate Revocation List) to check the revocation status of the signing certificate.")
    private String rootCrlSourceUrl;

    @Option(names = { "-tRCrl",
            "--tsaRootCrlUrl" }, description = "URL of the root CRL to be included in the signature for validation purposes when using CAdES-BASELINE-T or higher. Optional.")
    private String tsaRootCrlSourceUrl;

    // Verification options
    @Option(names = { "-v",
            "--verify" }, description = "Verify the signature of the input file.", defaultValue = "false")
    private boolean verify;

    @Option(names = {
            "--originalFile" }, description = "Path to the original file to be included in the signature when using detached packaging. Optional.")
    private File originalFile;

    @Option(names = { "-vp",
            "--validationPolicy" }, description = "Validation policy to use for signature verification (e.g., PKIX, CAdES). Optional")
    private File validationPolicy;

    @Option(names = { "-cs",
            "--cryptographicSuite" }, description = "Cryptographic suite to use for signature verification (e.g., BCPQC, NIST). Optional")
    private File cryptographicSuite;

    @Option(names = { "-sg",
            "--signingCertificate" }, description = "Path to a file containing the signing certificate to be used for signature verification. Optional")
    private File signingCertificate;

    @Option(names = { "-aj",
            "--adjunctCertificates" }, description = "Path to a file containing adjunct certificates to be included in the signature for validation purposes. Optional")
    private File adjunctCertificates; // TO-DO: Implement the option to load multiple

    @Option(names = { "-er",
            "--evidenceRecord" }, description = "Path to a file containing an evidence record to be included in the signature for validation purposes. Optional")
    private File evidenceRecord; // TO-DO: Implement the option to load multiple evidence records if needed

    @Option(names = { "-r",
            "--report" }, description = "Type of validation report to generate (simpleReport, validationReport, diagnosticReport). Default: simpleReport, validationReport, and diagnosticReport")
    private String reportType;

    @Option(names = { "-tl",
            "--tlSourceUrl" }, description = "URL or filepath of the Trusted List (TL) source to be used for signature verification and revocation data checking. Should point to an official EU TL or national TL. Optional.")
    private String tlSourceUrl;

    @Option(names = { "-aia",
            "--aiaSourceUrl" }, description = "URL of the Authority Information Access (AIA) source to be used for signature verification. Optional.", defaultValue = "null")
    private String aiaSourceUrl;

    @Option(names = { "-ocsp",
            "--ocspSourceUrl" }, description = "URL of the Online Certificate Status Protocol (OCSP) source to be used for signature verification. Optional.", defaultValue = "null")
    private String ocspSourceUrl;

    // TO-DO: Add the option to set "expected output" in which the user can specify
    // which output they want to get outputed in the CLI, e.g "Indication,
    // SubIndication, QualificationDetails, ..."

    private static String logFileName = null;

    // Define public variables
    private List<String> parameterValues = new ArrayList<>();
    private List<String> parameterNames = new ArrayList<>();

    // Initialize variables for signature token and signer entry
    private SignatureTokenConnection signatureToken = null;
    private DSSPrivateKeyEntry signerEntry = null;
    private DSSDocument signedDocument = null;

    // Get the signature level as a string for use in multiple checks
    private String signatureLevelString = null;

    // Initialize the certificate verifier
    private CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

    // Initialize the TLValidationJob
    private TLValidationJob tlValidationJob = new TLValidationJob();

    // Initialize the TrustedListsCertificateSource
    private TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

    // Initialize the CAdES service
    private CAdESService cadesService = new CAdESService(certificateVerifier);

    // Set up the CAdES signature parameters
    private CAdESSignatureParameters parameters = new CAdESSignatureParameters();

    // Initialize the document to be signed
    private DSSDocument documentToSign = null;

    // Initialize the data loader for CRL fetching with caching capabilities
    private FileCacheDataLoader cachedDataLoader = null;

    private CommonsDataLoader fileDataLoader = new CommonsDataLoader();

    private DocumentValidator documentValidator = null;

    private Reports finalReport = null;

    private String generateLogFileName(boolean sign, SignatureLevel signatureLevel, String timestamp) {
        String operation = sign ? "cades-sign" : "cades-verify";

        if (sign) {
            // For signing operations, append the signature level shorthand
            String signatureLevelExtension = null;

            switch (signatureLevel) {
                case CAdES_BASELINE_B:
                    signatureLevelExtension = "CAdES-B";
                    break;
                case CAdES_BASELINE_T:
                    signatureLevelExtension = "CAdES-T";
                    break;
                case CAdES_BASELINE_LT:
                    signatureLevelExtension = "CAdES-LT";
                    break;
                case CAdES_BASELINE_LTA:
                    signatureLevelExtension = "CAdES-LTA";
                    break;
                default:
                    signatureLevelExtension = "CAdES";
            }

            return operation + "-" + timestamp + "-" + signatureLevelExtension;
        } else {
            // For verification operations, just use operation name and timestamp
            return operation + "-" + timestamp;
        }
    }

    @Override
    public void run() {
        if (verify && sign) {
            logger.error(
                    "Options -s/--sign and -v/--verify cannot be used together. Please choose either signing or verification.");
            throw new ApplicationException(
                    "Options -s/--sign and -v/--verify cannot be used together. Please choose either signing or verification.");
        }

        // Ensure log directory exists and set logFileName
        try {
            File logDir = new File("log");
            if (!logDir.exists()) {
                logDir.mkdirs();
            }

            // Read properties from log4j2.xml configuration
            LoggerContext loggerContext = (LoggerContext) LogManager.getContext();
            java.util.Map<String, String> properties = loggerContext.getConfiguration().getProperties();
            String logDirProperty = properties.getOrDefault("logDir", "log");

            // Build the actual log file name with timestamp
            String timestamp = new java.text.SimpleDateFormat("yy-MM-dd-HH-mm-ss").format(new java.util.Date());
            String baseFileName = generateLogFileName(sign, signatureLevel, timestamp);
            logFileName = logDirProperty + File.separator + baseFileName + ".log";

            logger.info("Logging configured via log4j2.xml - Log file: " + logFileName);
        } catch (Exception e) {
            logger.warn("Could not create log directory: " + e.getMessage());
        }

        // Configure logging level based on user input
        try {
            Level log4jLevel = Level.getLevel(logLevel.toUpperCase());
            if (log4jLevel == null) {
                // If the level is not recognized, try to parse it
                log4jLevel = Level.INFO;
                logger.warn("Invalid log level specified: " + logLevel + ". Defaulting to INFO level.");
            }

            // Set the root logger level
            Configurator.setRootLevel(log4jLevel);

            // Set the CadesSign package logger level
            Configurator.setLevel("cades.de", log4jLevel);

            logger.info("Starting CAdES process with log level: " + log4jLevel);
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid log level specified: " + logLevel + ". Defaulting to INFO level.");
            Configurator.setRootLevel(Level.INFO);
            Configurator.setLevel("cades.de", Level.INFO);
        }

        if (!aiaSourceUrl.equals("null")) {
            throw new ApplicationException(
                    "Option -aia/--aiaSourceUrl is not yet implemented. Please remove this option or wait for a future release.");
        }

        if (!ocspSourceUrl.equals("null")) {
            throw new ApplicationException(
                    "Option -ocsp/--ocspSourceUrl is not yet implemented. Please remove this option or wait for a future release.");
        }

        // Output all the given parameters

        parameterValues.add(inputFile.getAbsolutePath());
        parameterValues.add(outputPath != null ? outputPath : "null");
        parameterValues.add(outputFile != null ? outputFile : "null");
        parameterValues.add(logLevel);
        parameterValues.add(Boolean.toString(sign));
        parameterValues.add(certFile != null ? certFile.getAbsolutePath() : "null");
        // parameterValues.add(certPassword != null ? "****" : "null");
        parameterValues.add(certPassword != null ? certPassword : "null");
        parameterValues.add(signatureLevel != null ? signatureLevel.name() : "null");
        parameterValues.add(signaturePackaging.name());
        parameterValues.add(signatureAlgorithm.name());
        parameterValues.add(tsaUrl != null ? tsaUrl : "null");
        parameterValues.add(trustAnchorAlias != null ? trustAnchorAlias : "null");
        parameterValues.add(intermediateCrlSourceUrl != null ? intermediateCrlSourceUrl : "null");
        parameterValues.add(rootCrlSourceUrl != null ? rootCrlSourceUrl : "null");
        parameterValues.add(tsaRootCrlSourceUrl != null ? tsaRootCrlSourceUrl : "null");
        parameterValues.add(Boolean.toString(verify));
        parameterValues.add(originalFile != null ? originalFile.getAbsolutePath() : "null");
        parameterValues.add(validationPolicy != null ? validationPolicy.getAbsolutePath() : "null");
        parameterValues.add(cryptographicSuite != null ? cryptographicSuite.getAbsolutePath() : "null");
        parameterValues.add(signingCertificate != null ? signingCertificate.getAbsolutePath() : "null");
        parameterValues.add(adjunctCertificates != null ? adjunctCertificates.getAbsolutePath() : "null");
        parameterValues.add(evidenceRecord != null ? evidenceRecord.getAbsolutePath() : "null");
        parameterValues.add(reportType);
        parameterValues.add(tlSourceUrl != null ? tlSourceUrl : "null");
        parameterValues.add(aiaSourceUrl != null ? aiaSourceUrl : "null");
        parameterValues.add(ocspSourceUrl != null ? ocspSourceUrl : "null");

        parameterNames.add("inputFile");
        parameterNames.add("outputPath");
        parameterNames.add("outputFile");
        parameterNames.add("logLevel");
        parameterNames.add("sign");
        parameterNames.add("certFile");
        parameterNames.add("certPassword");
        parameterNames.add("signatureLevel");
        parameterNames.add("signaturePackaging");
        parameterNames.add("signatureAlgorithm");
        parameterNames.add("tsaUrl");
        parameterNames.add("trustAnchorAlias");
        parameterNames.add("intermediateCrlSourceUrl");
        parameterNames.add("rootCrlSourceUrl");
        parameterNames.add("tsaRootCrlSourceUrl");
        parameterNames.add("verify");
        parameterNames.add("originalFile");
        parameterNames.add("validationPolicy");
        parameterNames.add("cryptographicSuite");
        parameterNames.add("signingCertificate");
        parameterNames.add("adjunctCertificates");
        parameterNames.add("evidenceRecord");
        parameterNames.add("reportType");
        parameterNames.add("tlSourceUrl");
        parameterNames.add("aiaSourceUrl");
        parameterNames.add("ocspSourceUrl");

        for (int i = parameterValues.size() - 1; i >= 0; i--) {
            logger.info("Parameter given: " + parameterNames.get(i) + " = " + parameterValues.get(i));
            if (parameterValues.get(i) == null || parameterValues.get(i).isEmpty()
                    || parameterValues.get(i).equals("null") || parameterValues.get(i).equals("false")) {
                parameterValues.remove(i);
                parameterNames.remove(i);
            }
        }
        logger.debug(parameterValues.size() + " Parameters provided: " + String.join(", ", parameterNames));

        if (sign) {
            // Validate that all required parameters for signing are provided
            if (signatureLevel == null) {
                throw new ApplicationException(
                        "Signature level must be specified when signing. Please provide a value for the -l/--signatureLevel option.");
            } else if (certPassword == null) {
                throw new ApplicationException(
                        "Certificate password must be specified when signing. Please provide a value for the -p/--password option.");
            } else if (certFile == null) {
                throw new ApplicationException(
                        "Certificate file must be specified when signing. Please provide a value for the -c/--cert option.");
            } else {
                logger.debug("All required parameters for signing are provided.");
                logger.info("Starting signing process...");
                sign();
            }
        }

        if (verify) {
            logger.info("Starting verification process...");
            verify();
        }
    }

    public void sign() {

        signatureLevelString = signatureLevel.toString();

        loadInputFileSigning();

        setDigestAlgorithm();
        setSignatureLevel();
        setSignaturePackaging();
        setValidationDataEncapsulationStrategy();

        configureTrustedList();

        getPrivateKeyEntries();
        setCertificateSources();

        setCertificateRevocationSource();
        setChainCertificate(getChainCertificate());
        setCertificateSigning(getCertificateSigning());

        getDataToSign();
        getSignatureValue();
        getSignatureParameters();

        signDocument();
        saveSignedDocument();

    }

    public void verify() {

        initializeVerify();

        setOriginalFile();
        setEvidenceRecord();
        setSigningCertificate();
        setTokenIdentifierProvider();
        setIncludeSemantics();

        setCertificateRevocationSource();

        getValidationPolicy();

        getReport();

    }

    public void initializeVerify() {
        try {
            logger.debug(inputFile.getAbsolutePath());
            FileDocument fileToValidate = new FileDocument(inputFile);
            logger.debug("Loaded signed file for validation: " + inputFile.getAbsolutePath());

            configureTrustedList();

            documentValidator = SignedDocumentValidator.fromDocument(fileToValidate);
            documentValidator.setCertificateVerifier(certificateVerifier);
            logger.debug("Initialized document validator for signature verification.");
            logger.debug("CertificateVerifier: \n" + certificateVerifier.toString());
            logger.debug("DocumentValidator: \n" + documentValidator.toString());
        } catch (Exception e) {
            logger.error("Error initializing signature verification: " + e.getMessage());
            throw new ApplicationException("Failed to initialize signature verification.", e);
        }
    }

    public void setOriginalFile() {
        try {
            logger.debug("Original file provided. Setting it as detached content for validation: "
                    + originalFile.getAbsolutePath());
            List<DSSDocument> originalDocuments = new ArrayList<>();
            originalDocuments.add(new FileDocument(originalFile));
            documentValidator.setDetachedContents(originalDocuments);
            logger.debug("Set original file as detached content for validation.");
        } catch (NullPointerException e) {
            logger.warn("No original file provided for validation. ");
        } catch (Exception e) {
            logger.error("Error setting original file for validation: " + e.getMessage());
            throw new ApplicationException("Failed to set original file for validation.", e);
        }
    }

    public void setEvidenceRecord() {
        try {
            logger.debug("Evidence record file provided. Setting it as detached evidence record for validation: "
                    + evidenceRecord.getAbsolutePath());
            logger.debug("TEST");
            List<DSSDocument> evidenceRecordDocuments = new ArrayList<>();
            evidenceRecordDocuments.add(new FileDocument(evidenceRecord));
            documentValidator.setDetachedEvidenceRecordDocuments(evidenceRecordDocuments);
        } catch (NullPointerException e) {
            logger.warn("No evidence record file provided for validation. ");
        } catch (Exception e) {
            logger.error("Error setting evidence record for validation: " + e.getMessage());
            throw new ApplicationException("Failed to set evidence record for validation.", e);
        }
    }

    public void setSigningCertificate() {
        try {
            // Load the signing certificate from the provided file and set it as a
            // certificate source for validation
            logger.debug("Signing certificate file provided. Loading it for validation: "
                    + signingCertificate.getAbsolutePath());
            CommonCertificateSource signingCertificateSource = new CommonCertificateSource();
            CertificateToken signingCertificateToken = null;

            // Check if the certificate file is in PEM format or Base64 encoded, and load it
            // accordingly
            byte[] certificateBytes = DSSUtils.toByteArray(signingCertificate);
            String certificateBytesString = new String(certificateBytes);
            if (!isPem(certificateBytes) && Utils.isBase64Encoded(certificateBytesString)) {
                signingCertificateToken = DSSUtils.loadCertificateFromBase64EncodedString(certificateBytesString);
            } else {
                // If the certificate is not in PEM format or Base64 encoded, try to load it as
                // a regular certificate file
                signingCertificateToken = DSSUtils.loadCertificate(certificateBytes);
            }

            // Add the loaded signing certificate to a certificate source
            signingCertificateSource.addCertificate(signingCertificateToken);

            // Set the certificate source containing the signing certificate as a signing
            // certificate source for validation
            documentValidator.setSigningCertificateSource(signingCertificateSource);
        } catch (NullPointerException e) {
            logger.warn("No signing certificate file provided for validation. ");
        } catch (Exception e) {
            logger.error("Error setting signing certificate for validation: " + e.getMessage());
            throw new ApplicationException("Failed to set signing certificate for validation.", e);
        }
    }

    public void setTokenIdentifierProvider() {
        try {
            documentValidator.setTokenIdentifierProvider(
                    true ? new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider());
            logger.debug("Set token identifier provider for validation.");
        } catch (Exception e) {
            logger.error("Error setting token identifier provider for validation: " + e.getMessage());
            throw new ApplicationException("Failed to set token identifier provider for validation.", e);
        }
    }

    public void setIncludeSemantics() {
        try {
            documentValidator.setIncludeSemantics(false);
            logger.debug("Set include semantics for validation to: false");
        } catch (Exception e) {
            logger.error("Error setting include semantics for validation: " + e.getMessage());
            throw new ApplicationException("Failed to set include semantics for validation.", e);
        }
    }

    public void getValidationPolicy() {
        try {
            logger.info(
                    "---------------------------------------- START: Validation Policy ----------------------------------------");
            finalReport = documentValidator.validateDocument(validationPolicy);
            logger.info(
                    "---------------------------------------- END: Validation Policy ----------------------------------------");
            logger.info("CAdES signature validation process completed. Validation report generated.");
        } catch (Exception e) {
            logger.error("Error during signature validation: " + e.getMessage());
            throw new ApplicationException("Failed to validate signature.", e);
        }
    }

    public void getReport() {
        getOutputFile(false);

        try {

            if (reportType == null || reportType.isEmpty()) {
                reportType = "fullReport";
            }

            logger.debug("Generating validation report based on user-specified report type: " + reportType);
            switch (reportType) {
                // Generate the simple report if the user has specified "simpleReport" as the
                // report type
                case "simpleReport":
                    generateSimpleReport();
                    break;
                // Generate the validation report if the user has specified "validationReport"
                // as the report type
                case "validationReport":
                    generateValidationReport();
                    break;
                case "diagnosticReport":
                    generateDiagnosticsReport();
                    break;
                // Generate no report if the user has specified "none" as the report type
                case "none":
                    logger.info("No report will be generated as per user specification.");
                    break;
                // Generate the full report (both simple report and validation report) if the
                // user has specified any other value as the report type or if the report type
                // is not specified
                default:
                    generateFullReport();
            }
        } catch (Exception e) {
            logger.error("Error generating validation report: " + e.getMessage());
            throw new ApplicationException("Failed to generate validation report.", e);
        }
    }

    public void generateSimpleReport() {
        logger.debug("Generating simple report for validation results.");
        outputFile += "_simple_report.xml";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            logger.debug("Writing simple report to file: " + outputFile);
            writer.write(finalReport.getXmlSimpleReport());
            writer.flush();
            logger.info("Simple report saved to: " + outputFile);
        } catch (Exception e) {
            logger.error("Error saving simple report: " + e.getMessage(), e);
        }
    }

    public void generateValidationReport() {
        logger.debug("Generating validation report for validation results.");
        outputFile += "_validation_report.xml";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            logger.debug("Writing validation report to file: " + outputFile);
            writer.write(finalReport.getXmlValidationReport());
            writer.flush();
            logger.info("Validation report saved to: " + outputFile);
        } catch (Exception e) {
            logger.error("Error saving validation report: " + e.getMessage(), e);
        }
    }

    public void generateDiagnosticsReport() {
        logger.debug("Generating diagnostic report for validation results.");
        outputFile += "_diagnostic_report.xml";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            logger.debug("Writing diagnostic report to file: " + outputFile);

            JAXBContext context = JAXBContext.newInstance(finalReport.getDiagnosticDataJaxb().getClass());
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            // Wrap the diagnostic data in a JAXBElement since XmlDiagnosticData lacks
            // @XmlRootElement
            jakarta.xml.bind.JAXBElement<Object> element = new jakarta.xml.bind.JAXBElement<>(
                    new javax.xml.namespace.QName("http://www.isdpd.ec.europa.eu/tools/dss/diagnostic",
                            "DiagnosticData"),
                    Object.class,
                    finalReport.getDiagnosticDataJaxb());
            marshaller.marshal(element, writer);
            writer.flush();
            logger.info("Diagnostic report saved to: " + outputFile);
        } catch (Exception e) {
            logger.error("Error saving diagnostic report: " + e.getMessage(), e);
        }
    }

    public void generateFullReport() {
        logger.debug("Generating full report for validation results.");
        outputFile += "_full_report.xml";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            logger.debug("Writing full report to file: " + outputFile);
            writer.write("SimpleReport:\n" + finalReport.getXmlSimpleReport()
                    + "\n\nValidationReport:\n" + finalReport.getXmlValidationReport()
                    + "\n\nDiagnosticReport:\n");
            writer.flush();

            JAXBContext context = JAXBContext
                    .newInstance(finalReport.getDiagnosticDataJaxb().getClass());
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            // Wrap the diagnostic data in a JAXBElement since XmlDiagnosticData lacks
            // @XmlRootElement
            jakarta.xml.bind.JAXBElement<Object> element = new jakarta.xml.bind.JAXBElement<>(
                    new javax.xml.namespace.QName("http://www.isdpd.ec.europa.eu/tools/dss/diagnostic",
                            "DiagnosticData"),
                    Object.class,
                    finalReport.getDiagnosticDataJaxb());
            marshaller.marshal(element, writer);
            writer.flush();
            logger.info("Full validation report saved to: " + outputFile);
        } catch (Exception e) {
            logger.error("Error saving full validation report: " + e.getMessage(), e);
        }
    }

    public void loadInputFileSigning() {
        documentToSign = new FileDocument(inputFile);
        logger.debug("Loaded input file: " + inputFile.getAbsolutePath());
    }

    public void configureTrustedList() {
        if (tlSourceUrl == null || tlSourceUrl.isEmpty()) {
            logger.debug("No TrustedList source provided. Skipping TL configuration.");
            return;
        }

        try {
            logger.info("Configuring TrustedList source: " + tlSourceUrl);

            // Convert local filepath to file:// URL if needed
            String tlUrl = convertToFileUrl(tlSourceUrl);
            logger.debug("Converted TL source to URL format: " + tlUrl);

            // Create and configure the TL source
            TLSource tlSource = new TLSource();
            tlSource.setUrl(tlUrl);
            tlValidationJob.setTrustedListSources(tlSource);
            logger.debug("Set TL source URL: " + tlUrl);

            // Create the TrustedListsCertificateSource
            TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
            tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);
            logger.debug("Created and configured TrustedListsCertificateSource.");

            // Set up data loaders for TL refresh
            // The onlineRefresh() method requires an onlineLoader to fetch remote TLs

            setOnlineDataLoader();
            // Also set offline loader for offline validation
            tlValidationJob.setOfflineDataLoader(offlineLoader());
            logger.debug("Set offline data loader for TLValidationJob.");

            // Refresh and load the TrustedList
            tlValidationJob.onlineRefresh();
            logger.info("TrustedList refresh completed. Loaded "
                    + trustedListsCertificateSource.getNumberOfCertificates() + " certificate(s).");

            if (sign) {
                // Add the TrustedListsCertificateSource to the certificate verifier
                // ONLY for BASELINE-B: Adding this for T/LT causes validation errors
                if (signatureLevel.toString().equals("CAdES_BASELINE_B")) {
                    certificateVerifier.addTrustedCertSources(trustedListsCertificateSource);
                    logger.info(
                            "TrustedListsCertificateSource added to certificate verifier for BASELINE-B signature.");
                } else {
                    logger.info("Skipping TrustedListsCertificateSource addition for " + signatureLevel
                            + " due to DSS validation conflicts during extension.");
                }
            }

        } catch (Exception e) {
            logger.error("Error configuring TrustedList: " + e.getMessage());
            e.printStackTrace();
            logger.warn(
                    "TrustedList configuration failed. Continuing without TL. Revocation checking may fail for untrusted chains.");
        }
    }

    public void setOnlineDataLoader() {
        try {
            CommonsDataLoader dataLoader = new CommonsDataLoader();
            FileCacheDataLoader cachedDataLoader = new FileCacheDataLoader(dataLoader);
            cachedDataLoader.setFileCacheDirectory(getTLCacheDirectory());
            cachedDataLoader.setCacheExpirationTime(-1); // cache never expires

            tlValidationJob.setOnlineDataLoader(cachedDataLoader);
            logger.debug("Set online data loader with cache for TLValidationJob.");
        } catch (Exception e) {
            logger.warn("Could not configure online data loader for TLValidationJob: " + e.getMessage());
        }
    }

    public void setCertificateRevocationSource() {

        CommonsDataLoader fileDataLoader = new CommonsDataLoader();
        FileCacheDataLoader cachedDataLoader = new FileCacheDataLoader(fileDataLoader);
        cachedDataLoader.setFileCacheDirectory(getCRLCacheDirectory());
        cachedDataLoader.setCacheExpirationTime(-1);

        // Load DER CRL files into the cache
        loadCRLFile(intermediateCrlSourceUrl, cachedDataLoader);
        loadCRLFile(rootCrlSourceUrl, cachedDataLoader);
        loadCRLFile(tsaRootCrlSourceUrl, cachedDataLoader);

        // Use OnlineCRLSource with cached data loader to serve CRLs
        OnlineCRLSource onlineCrlSource = new OnlineCRLSource(cachedDataLoader);
        certificateVerifier.setCrlSource(onlineCrlSource);
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        logger.info("Configured OnlineCRLSource with file cache for CRL loading");
    }

    /**
     * Load a CRL file (DER format) into the cache so it can be embedded in the
     * signature
     */
    private void loadCRLFile(String crlFilePath, FileCacheDataLoader cachedDataLoader) {
        if (crlFilePath == null || crlFilePath.trim().isEmpty()) {
            return;
        }

        File crlFile = new File(crlFilePath);
        try {
            logger.info("Loading CRL file: " + crlFile.getAbsolutePath());
            if (!crlFile.exists()) {
                logger.warn("CRL file does not exist: " + crlFilePath);
                return;
            }

            String fileUrl = "file://" + crlFile.getAbsolutePath();
            byte[] crlBytes = cachedDataLoader.get(fileUrl);

            if (crlBytes != null && crlBytes.length > 0) {
                logger.info("CRL loaded successfully, size: " + crlBytes.length + " bytes");
            } else {
                logger.warn("CRL file data is empty or could not be loaded: " + crlFilePath);
            }
        } catch (Exception e) {
            logger.warn("Could not load CRL file: " + crlFilePath + " - " + e.getMessage(), e);
        }
    }

    public void setDigestAlgorithm() {
        try {
            // Set the digest algorithm
            parameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
            logger.debug("Set digest algorithm: " + signatureAlgorithm.getDigestAlgorithm());
        } catch (Exception e) {
            logger.warn("Could not set digest algorithm: " + e.getMessage());
            throw new ApplicationException("Failed to set digest algorithm.", e);
        }
    }

    public void setSignatureLevel() {
        try {
            // Set the signature level
            parameters.setSignatureLevel(signatureLevel);
            logger.debug("Set signature level to: " + signatureLevel);
        } catch (Exception e) {
            logger.error("Error setting signature level: " + e.getMessage());
            throw new ApplicationException("Failed to set signature level.", e);
        }
    }

    public void setSignaturePackaging() {
        try {
            // Set the signature packaging
            parameters.setSignaturePackaging(signaturePackaging);
            logger.debug("Set signature packaging to: " + signaturePackaging);
        } catch (Exception e) {
            logger.error("Error setting signature packaging: " + e.getMessage());
            throw new ApplicationException("Failed to set signature packaging.", e);
        }
    }

    public void setCadesTimestampParameters() {
        try {
            CAdESTimestampParameters timestampParams = new CAdESTimestampParameters();
            cadesService.setTspSource(new OnlineTSPSource(tsaUrl));
            logger.debug("Configured Time Stamping Authority (TSA) with URL: " + tsaUrl);

            parameters.setContentTimestampParameters(timestampParams);
            logger.debug("Set timestamp parameters for content timestamp.");

            // Set the timestamp parameter for the -T level
            parameters.setSignatureTimestampParameters(timestampParams);
            logger.debug("Set timestamp parameters for signature timestamp.");

            // Set the timestamp parameter for the -LTA level
            parameters.setArchiveTimestampParameters(timestampParams);
            logger.debug("Set timestamp parameters for archive timestamp.");

        } catch (Exception e) {
            logger.error("Error configuring Time Stamping Authority (TSA): " + e.getMessage());
            throw new ApplicationException("Failed to configure TSA.", e);
        }
    }

    public void setValidationDataEncapsulationStrategy() {
        try {
            parameters.setValidationDataEncapsulationStrategy(
                    ValidationDataEncapsulationStrategy.ANY_VALIDATION_DATA_ONLY);
            logger.debug("Set validation data encapsulation strategy to: "
                    + parameters.getValidationDataEncapsulationStrategy());
        } catch (Exception e) {
            logger.error("Error setting validation data encapsulation strategy: " + e.getMessage());
            throw new ApplicationException("Failed to set validation data encapsulation strategy.", e);
        }
    }

    public void setCertificateSources() {
        try {
            KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(certFile, "PKCS12",
                    certPassword.toCharArray());
            logger.debug("Set a total of " + keyStoreCertificateSource.getNumberOfCertificates()
                    + " certificate(s) from the PKCS12 file as a certificate source for validation.");

            CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
            // Add all certificates from the PKCS12 file
            int i = 0;
            for (CertificateToken cert : keyStoreCertificateSource.getCertificates()) {
                adjunctCertificateSource.addCertificate(cert);
                i++;
            }
            logger.debug("Added " + i
                    + " certificate(s) from PKCS12 file to CommonCertificateSource for adjunct certificate source.");

            // Add the full certificate chain from the private key entry if available
            if (signerEntry != null && signerEntry.getCertificateChain() != null) {
                CertificateToken[] chain = signerEntry.getCertificateChain();
                logger.debug(
                        "Adding " + chain.length + " certificate(s) from private key entry chain to adjunct source.");
                for (CertificateToken chainCert : chain) {
                    adjunctCertificateSource.addCertificate(chainCert);
                }
            }

            certificateVerifier.setAdjunctCertSources(adjunctCertificateSource);
            logger.debug(
                    "Added all certificates from PKCS12 file as adjunct certificate source for revocation data fetching.");

            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            trustedCertificateSource.importAsTrusted(keyStoreCertificateSource);

            // Also add the full certificate chain from the private key entry as trusted
            if (signerEntry != null && signerEntry.getCertificateChain() != null) {
                CertificateToken[] chain = signerEntry.getCertificateChain();
                logger.debug(
                        "Adding " + chain.length + " certificate(s) from private key entry chain to trusted source.");
                for (CertificateToken chainCert : chain) {
                    trustedCertificateSource.addCertificate(chainCert);
                }
            }

            logger.debug("Loaded PKCS12 keystore and imported certificates as trusted certificates for validation.");
            logger.info("Set a total of " + trustedCertificateSource.getNumberOfCertificates()
                    + " certificate(s) from the PKCS12 file as trusted certificates for validation.");
            logger.debug("Trusted certificates: " + trustedCertificateSource.getCertificates());

            logger.debug("Adjunct certificates (" + adjunctCertificateSource.getNumberOfCertificates() + "): "
                    + adjunctCertificateSource.getCertificates().toString());

            // CAUSES ERROR Signing-certificate token was not found!
            // certificateVerifier.addTrustedCertSources(trustedCertificateSource);
        } catch (Exception e) {
            logger.error("Error loading PKCS12 keystore: " + e.getMessage());
            throw new ApplicationException("Failed to load PKCS12 keystore.", e);
        }
    }

    public void getPrivateKeyEntries() {
        try {
            // Load the PKCS12 keystore
            signatureToken = new Pkcs12SignatureToken(certFile, new PasswordProtection(certPassword.toCharArray()));
            logger.debug("Initialized PKCS12 signature token with keystore: " + certFile.getAbsolutePath());

            // Extract the private key entry from the signature token
            List<DSSPrivateKeyEntry> privateKeyEntries = signatureToken.getKeys();
            if (privateKeyEntries == null || privateKeyEntries.isEmpty()) {
                throw new ApplicationException("No private key found in PKCS12 file: " + certFile.getAbsolutePath());
            }
            logger.debug(
                    "Extracted " + privateKeyEntries.size() + " private key entry(ies) from the signature token.");

            // Using the first private key entry for signing
            // TO-DO: Add an option to select a specific private key entry if there are
            // multiple entries in the PKCS12 file.
            signerEntry = privateKeyEntries.get(0);
            logger.debug("Selected private key entry for signing.");
        } catch (Exception e) {
            logger.error("Error loading PKCS12 keystore or extracting private key: " + e.getMessage());
            throw new ApplicationException("Failed to load PKCS12 keystore or extract private key.", e);
        }
    }

    public void setCertificateSigning(CertificateToken signingCertificate) {
        logger.debug("Called setCertificateSigning with signing certificate: " + signingCertificate);
        try {
            // Set the signing certificate
            parameters.setSigningCertificate(signingCertificate);
            logger.debug("Set signing certificate in signature parameters.");

            CertificateSource signingCertificateSource = new CommonTrustedCertificateSource();
            logger.debug("Created CommonTrustedCertificateSource for signing certificate.");
            signingCertificateSource.addCertificate(signingCertificate);
            logger.debug("Added signing certificate to CommonTrustedCertificateSource: " + signingCertificate);
            // CAUSES ERROR Signing-certificate token was not found!
            // certificateVerifier.addTrustedCertSources(signingCertificateSource);

            logger.debug("Set signing certificate as a trusted certificate source for validation.");
        } catch (Exception e) {
            logger.error("Error setting signing certificate: " + e.getMessage());
            throw new ApplicationException("Failed to set signing certificate.", e);
        }
    }

    public CertificateToken getCertificateSigning() {
        try {
            // Extract the signing certificate from the signature token
            CertificateToken signingCertificate = signerEntry.getCertificate();
            logger.debug("Extracted signing certificate from signature token.");
            return signingCertificate;
        } catch (Exception e) {
            logger.error("Error extracting signing certificate: " + e.getMessage());
            throw new ApplicationException("Failed to extract signing certificate.", e);
        }
    }

    public void setChainCertificate(CertificateToken[] chain) {
        try {
            parameters.setCertificateChain(chain);
            logger.debug("Set certificate chain in signature parameters with " + chain.length + " certificate(s).");

            // Register chain certificates with verifier for validation during extension
            if (chain != null && chain.length > 1) {
                CommonCertificateSource chainCertificateSource = new CommonCertificateSource();
                logger.debug(
                        "Adding intermediate and root certificates from chain to verifier for validation during extension.");

                for (int i = 1; i < chain.length; i++) {
                    chainCertificateSource.addCertificate(chain[i]);
                    logger.debug("Added certificate to chain certificate source: " + chain[i]);
                }

                if (chainCertificateSource.getNumberOfCertificates() > 0) {
                    logger.debug("Created CommonCertificateSource for chain certificates with "
                            + chainCertificateSource.getNumberOfCertificates() + " certificate(s).");
                    certificateVerifier.setAdjunctCertSources(chainCertificateSource);
                    logger.debug("Added " + chainCertificateSource.getNumberOfCertificates()
                            + " intermediate/root certificate(s) from chain to verifier.");
                }

                // For BASELINE-T/LT: Add root certificate as trusted anchor to avoid "untrusted
                // chain" errors
                if (!signatureLevel.toString().equals("CAdES_BASELINE_B") && chain.length > 1) {
                    CertificateToken rootCert = chain[chain.length - 1]; // Last cert is root
                    logger.debug("Adding root certificate from chain as trusted anchor for " + signatureLevel
                            + " to avoid untrusted chain errors during validation: " + rootCert);
                    CommonTrustedCertificateSource rootTrustedSource = new CommonTrustedCertificateSource();
                    rootTrustedSource.addCertificate(rootCert);
                    certificateVerifier.addTrustedCertSources(rootTrustedSource);
                    logger.info("Added root certificate as trusted anchor for " + signatureLevel + " signature.");

                    // // For BASELINE-LT: Also add intermediate CA as trusted to complete the chain
                    // // validation
                    // CertificateToken intermediateCert = chain[chain.length - 2]; //
                    // Second-to-last is intermediate
                    // CommonTrustedCertificateSource intermediateTrustedSource = new
                    // CommonTrustedCertificateSource();
                    // intermediateTrustedSource.addCertificate(intermediateCert);
                    // certificateVerifier.addTrustedCertSources(intermediateTrustedSource);
                    // logger.info("Added intermediate CA certificate as trusted anchor for
                    // BASELINE-LT signature.");

                    // CertificateToken leadCert = chain[chain.length - 3]; // Third-to-last is lead
                    // CommonTrustedCertificateSource leadTrustedSource = new
                    // CommonTrustedCertificateSource();
                    // leadTrustedSource.addCertificate(leadCert);
                    // certificateVerifier.addTrustedCertSources(leadTrustedSource);
                    // logger.info("Added intermediate CA certificate as trusted anchor for
                    // BASELINE-LT signature.");
                }
            }
        } catch (Exception e) {
            logger.error("Error setting certificate chain: " + e.getMessage());
            throw new ApplicationException("Failed to set certificate chain.", e);
        }
    }

    public CertificateToken[] getChainCertificate() {
        try {
            // Extract the certificate chain from the signature token
            CertificateToken[] chain = signerEntry.getCertificateChain();

            logger.debug(
                    "Extracted certificate chain from signature token with " + chain.length + " certificate(s).");
            return chain;
        } catch (Exception e) {
            logger.error("Error extracting certificate chain: " + e.getMessage());
            throw new ApplicationException("Failed to extract certificate chain.", e);
        }
    }

    public void getCertificateVerifierData() {
        try {
            logger.debug("================================ CERTIFICATE VERIFIER DATA ================================");

            // Check if verifier exists
            if (certificateVerifier == null) {
                logger.debug("Certificate verifier is NULL");
                return;
            }

            // Log Trusted Certificate Sources
            logger.debug("--- TRUSTED CERTIFICATE SOURCES ---");
            ListCertificateSource trustedSources = certificateVerifier.getTrustedCertSources();
            if (trustedSources != null) {
                logger.debug("Trusted sources type: " + trustedSources.getClass().getSimpleName());
                List<CertificateToken> sourceList = trustedSources.getCertificates();
                if (sourceList != null && !sourceList.isEmpty()) {
                    logger.debug("Number of trusted certificate sources: " + sourceList.size());
                    for (int i = 0; i < sourceList.size(); i++) {
                        CertificateToken source = sourceList.get(i);
                        logger.debug("  [" + i + "] " + source.getClass().getSimpleName());
                        logger.debug("      - Certificates: " + source.toString());
                    }
                } else {
                    logger.debug("No trusted certificate sources configured");
                }
            } else {
                logger.debug("No trusted certificate sources configured");
            }

            // Log Adjunct Certificate Sources
            logger.debug("--- ADJUNCT CERTIFICATE SOURCES ---");
            CertificateSource adjunctSources = certificateVerifier.getAdjunctCertSources();
            if (adjunctSources != null) {
                logger.debug("Type: " + adjunctSources.getClass().getSimpleName());
                logger.debug("Certificates: " + adjunctSources.getCertificates());
            } else {
                logger.debug("No adjunct certificate sources configured");
            }

            // Log CRL Source
            logger.debug("--- CRL SOURCE ---");
            RevocationSource<?> crlSource = certificateVerifier.getCrlSource();
            if (crlSource != null) {
                logger.debug("CRL Source type: " + crlSource.getClass().getSimpleName());

                if (crlSource instanceof FileCacheCRLSource) {
                    FileCacheCRLSource fileCrlSource = (FileCacheCRLSource) crlSource;
                    logger.debug("FileCacheCRLSource details:");
                    logger.debug("  - Class: " + fileCrlSource.getClass().getName());

                    try {
                        // Discover all declared fields in FileCacheCRLSource and parent classes
                        Class<?> clazz = fileCrlSource.getClass();
                        logger.debug("  - Available fields in " + clazz.getSimpleName() + ":");
                        for (java.lang.reflect.Field field : clazz.getDeclaredFields()) {
                            field.setAccessible(true);
                            logger.debug("    Field: " + field.getName() + " = " + field.get(fileCrlSource));
                        }

                        // Check parent class fields
                        Class<?> parentClass = clazz.getSuperclass();
                        if (parentClass != null) {
                            logger.debug("  - Available fields in parent " + parentClass.getSimpleName() + ":");
                            for (java.lang.reflect.Field field : parentClass.getDeclaredFields()) {
                                field.setAccessible(true);
                                logger.debug("    Field: " + field.getName() + " = " + field.get(fileCrlSource));
                            }
                        }
                    } catch (Exception e) {
                        logger.debug("  - Error accessing fields: " + e.getMessage());
                    }
                } else if (crlSource instanceof OnlineCRLSource) {
                    OnlineCRLSource onlineCrlSource = (OnlineCRLSource) crlSource;
                    logger.debug("OnlineCRLSource details:");
                    logger.debug("  - Class: " + onlineCrlSource.getClass().getName());
                } else {
                    logger.debug("CRL Source details:");
                    logger.debug("  - Class: " + crlSource.getClass().getName());
                }
            } else {
                logger.debug("No CRL source configured");
            }

            // Log OCSP Source
            logger.debug("--- OCSP SOURCE ---");
            RevocationSource<?> ocspSource = certificateVerifier.getOcspSource();
            if (ocspSource != null) {
                logger.debug("OCSP Source type: " + ocspSource.getClass().getSimpleName());
                logger.debug("OCSP Source: " + ocspSource.toString());
            } else {
                logger.debug("No OCSP source configured");
            }

            logger.debug(
                    "================================ END CERTIFICATE VERIFIER DATA ================================");

        } catch (Exception e) {
            logger.error("Error getting certificate verifier data: " + e.getMessage());
            logger.debug("Exception details: ", e);
        }
    }

    public ToBeSigned getDataToSign() {

        try {
            getCertificateVerifierData();
        } catch (Exception e) {
            logger.error("Error getting certificate verifier data: " + e.getMessage());
        }

        try {
            // Reinitialize CAdESService with the fully configured certificate verifier
            cadesService = new CAdESService(certificateVerifier);
            logger.debug("Reinitialized CAdESService with configured certificate verifier for signature generation.");

            getCertificateVerifierData();
            logger.debug("Called getCertificateVerifierData()");

        } catch (Exception e) {
            logger.warn("Could not reinitialize CAdESService with configured certificate verifier: " + e.getMessage());
        }

        try {
            // Get the data to be signed from the CAdES service
            ToBeSigned toBeSigned = cadesService.getDataToSign(documentToSign, parameters);
            logger.debug("Obtained data to sign from CAdES service.");
            return toBeSigned;
        } catch (Exception e) {
            logger.error("Error obtaining data to sign: " + e.getMessage());
            throw new ApplicationException("Failed to obtain data to sign.", e);
        }
    }

    public SignatureValue getSignatureValue() {
        try {
            SignatureValue signatureValue = signatureToken.sign(getDataToSign(), signatureAlgorithm, signerEntry);
            logger.debug("Created signature value with algorithm " + signatureAlgorithm);

            logger.debug(
                    "------------------------------------------------ Verificator ------------------------------------------------");
            getCertificateVerifierData();
            return signatureValue;
        } catch (Exception e) {
            logger.error("Error creating signature value: " + e.getMessage());
            throw new ApplicationException("Failed to create signature value.", e);
        }
    }

    public void getSignatureParameters() {
        logger.debug("--------------------------- START: Signature Parameters ---------------------------");
        logger.debug("These are the parameters used for signing: \n" + parameters.toString());
        logger.debug("--------------------------- END: Signature Parameters ---------------------------");
    }

    public void signDocument() {

        setCadesTimestampParameters();
        logger.debug("Called setCadesTimestampParameters()");

        try {
            // Sign the document using the CAdES service
            signedDocument = cadesService.signDocument(documentToSign, parameters, getSignatureValue());
            logger.debug("Signed the document using CAdES service.");
        } catch (Exception e) {
            logger.error("Error signing the document: " + e.getMessage());
            throw new ApplicationException("Failed to sign the document.", e);
        }
    }

    public String getOutputPath() {
        if (outputPath == null || outputPath.isEmpty()) {
            logger.warn("No output path specified. Defaulting to input file path for output.");
            outputFile = inputFile.getAbsolutePath();

            outputFile = outputFile.substring(0, outputFile.lastIndexOf("."));
        } else {

            File outputPathDirectory = new File(outputPath);
            if (!outputPathDirectory.exists()) {
                outputPathDirectory.mkdirs();
            }

            // Get the filename without extension
            String fileName = inputFile.getName();
            String fileNameWithoutExtension = fileName.substring(0, fileName.lastIndexOf("."));

            // Combine directory path with filename (without extension)
            outputFile = outputPathDirectory.getAbsolutePath() + File.separator + fileNameWithoutExtension;
        }
        return outputFile;
    }

    public String getOutputFile(boolean sign) {
        try {
            if (sign) {
                if (outputFile == null || outputFile.isEmpty()) {
                    logger.warn("No output file specified. Generating default output file name based on input file.");

                    String extension = null;
                    if (signaturePackaging.toString().equals("ENVELOPING")) {
                        extension = ".p7m";
                    } else {
                        extension = ".p7s";
                    }

                    outputFile = getOutputPath();
                    outputFile = outputFile + "-" + signatureLevel.toString() + extension;
                    return outputFile;
                } else {
                    logger.debug("Using specified output file: " + outputFile);
                    return outputFile;
                }
            } else {
                logger.warn(
                        "No output file specified for validation report. Generating default output file name based on input file.");
                outputFile = getOutputPath();
                logger.debug("Base output file name generated: " + outputFile);
                return outputFile;
            }
        } catch (Exception e) {
            logger.error("Error generating output file name: " + e.getMessage());
            throw new ApplicationException("Failed to generate output file name.", e);
        }
    }

    public void saveSignedDocument() {
        try {
            // Save the signed document to the specified output file
            signedDocument.save(getOutputFile(true));
            logger.info("Signed document saved successfully to: " + getOutputFile(true));
        } catch (Exception e) {
            logger.error("Error saving signed document: " + e.getMessage());
            throw new ApplicationException("Failed to save signed document.", e);
        }
    }

    // Helper methods

    /**
     * Get the cache directory for TL files.
     * Extracts just the filename from the tlSourceUrl to avoid nested path issues.
     */
    public File getTLCacheDirectory() {
        File rootFolder = new File("cache");

        // Extract just the filename from the tlSourceUrl (e.g., "test.xml" from
        // "/path/to/test.xml")
        String cacheSubdir;
        if (tlSourceUrl.contains("/")) {
            cacheSubdir = tlSourceUrl.substring(tlSourceUrl.lastIndexOf("/") + 1);
        } else if (tlSourceUrl.contains("\\")) {
            cacheSubdir = tlSourceUrl.substring(tlSourceUrl.lastIndexOf("\\") + 1);
        } else {
            cacheSubdir = tlSourceUrl;
        }

        // If it's a URL, extract just the domain or use a default cache name
        if (tlSourceUrl.startsWith("http://") || tlSourceUrl.startsWith("https://")) {
            try {
                URL url = new URL(tlSourceUrl);
                cacheSubdir = url.getHost() + "_tl_cache";
            } catch (Exception e) {
                logger.warn("Could not parse URL for cache directory: " + e.getMessage());
                cacheSubdir = "tl_cache";
            }
        }

        File tslCache = new File(rootFolder, cacheSubdir);
        logger.debug("TL Cache folder set to: {}", tslCache.getAbsolutePath());
        if (tslCache.mkdirs()) {
            logger.debug("TL Cache folder created: {}", tslCache.getAbsolutePath());
        }
        return tslCache;
    }

    public DSSCacheFileLoader offlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(-1); // negative value means cache never expires
        offlineFileLoader.setDataLoader(new IgnoreDataLoader());
        offlineFileLoader.setFileCacheDirectory(getTLCacheDirectory());
        return offlineFileLoader;
    }

    public File getCRLCacheDirectory() {
        File rootFolder = new File("cache");

        // Default cache subdirectory name
        String cacheSubdir = "crl_cache";

        // // If crlSourceUrl is provided, extract a more specific directory name
        // if (crlSourceUrl != null && !crlSourceUrl.isEmpty()) {
        // if (crlSourceUrl.contains("/")) {
        // cacheSubdir = crlSourceUrl.substring(crlSourceUrl.lastIndexOf("/") + 1);
        // } else if (crlSourceUrl.contains("\\")) {
        // cacheSubdir = crlSourceUrl.substring(crlSourceUrl.lastIndexOf("\\") + 1);
        // } else {
        // cacheSubdir = crlSourceUrl;
        // }

        // // If it's a URL, extract just the domain or use a default cache name
        // if (crlSourceUrl.startsWith("http://") ||
        // crlSourceUrl.startsWith("https://")) {
        // try {
        // URL url = new URL(crlSourceUrl);
        // cacheSubdir = url.getHost() + "_crl_cache";
        // } catch (Exception e) {
        // logger.warn("Could not parse URL for cache directory: " + e.getMessage());
        // cacheSubdir = "crl_cache";
        // }
        // }
        // }

        File crlCache = new File(rootFolder, cacheSubdir);
        logger.debug("CRL Cache folder set to: {}", crlCache.getAbsolutePath());
        if (crlCache.mkdirs()) {
            logger.debug("CRL Cache folder created: {}", crlCache.getAbsolutePath());
        }
        return crlCache;
    }

    public DSSCacheFileLoader crlOfflineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(-1); // negative value means cache never expires
        offlineFileLoader.setDataLoader(new IgnoreDataLoader());
        offlineFileLoader.setFileCacheDirectory(getCRLCacheDirectory());
        return offlineFileLoader;
    }

    /**
     * Convert a local filepath to a file:// URL.
     * If already a URL (http, https, ftp, ldap), returns as-is.
     * If a local filepath, converts to file:// URL format.
     * 
     * @param path The filepath or URL to convert
     * @return A valid file:// URL or the original URL
     */
    private String convertToFileUrl(String path) {
        // If it's already a proper URL, return as-is
        if (path.startsWith("http://") || path.startsWith("https://") ||
                path.startsWith("ftp://") || path.startsWith("ldap://") ||
                path.startsWith("file://")) {
            return path;
        }

        // Convert local filepath to file:// URL
        try {
            File file = new File(path);
            String absolutePath = file.getAbsolutePath();

            // Convert Windows path separators to forward slashes
            absolutePath = absolutePath.replace("\\", "/");

            // Add file:// prefix
            // For absolute paths on Unix (starting with /), use file://path
            // For absolute paths on Windows (like C:/), use file:///C:/path
            if (absolutePath.startsWith("/")) {
                return "file://" + absolutePath;
            } else {
                return "file:///" + absolutePath;
            }
        } catch (Exception e) {
            logger.warn("Could not convert path to file URL: " + e.getMessage() + ". Using path as-is.");
            return path;
        }
    }

    private static boolean isPem(byte[] string) {
        return Utils.startsWith(string, "-----".getBytes());
    }

    public static void main(String[] args) {
        int exitCode = new picocli.CommandLine(new CadesSign()).execute(args);

        // Rename the base log file to the timestamped name before exiting
        try {
            File baseLogFile = new File("log/cades-sign.log");
            if (baseLogFile.exists() && logFileName != null && !logFileName.isEmpty()) {
                File targetLogFile = new File(logFileName);
                if (baseLogFile.renameTo(targetLogFile)) {
                    logger.debug("Successfully renamed log file from " + baseLogFile.getAbsolutePath() +
                            " to " + targetLogFile.getAbsolutePath());
                } else {
                    logger.warn("Failed to rename log file from " + baseLogFile.getAbsolutePath() +
                            " to " + targetLogFile.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            logger.warn("Error renaming log file: " + e.getMessage());
        }

        logger.info("Log trace available in log file for debugging if needed: " + logFileName);

        System.exit(exitCode);
    }
}