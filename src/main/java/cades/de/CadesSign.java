package cades.de;

import cades.de.exception.ApplicationException;

import java.io.IOException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.security.KeyStore.PasswordProtection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.LoggerContext;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.spi.x509.aia.AIASource;

import eu.europa.esig.dss.validation.DocumentValidator;

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

	@Option(names = { "-o",
			"--output" }, description = "Path to the output file where the signed data will be saved. If not specified, the signed file will be saved in the same directory as the input file with a default name based on the input file name and signature level. Optional.")
	private String outputFile;

	@Option(names = { "-t",
			"--tsaUrl" }, description = "URL of the Time Stamping Authority (TSA) to include a timestamp in the signature. Required, if signature level is higher than CAdES-BASELINE-B")
	private String tsaUrl;

	@Option(names = { "-ta",
			"--trustAnchorAlias" }, description = "Alias of the certificate from the PKCS12 file to be used as the trusted anchor. If not specified, all certificates in the trust chain will be listed for selection. Optional for signing.")
	private String trustAnchorAlias;

	@Option(names = { "-crl",
			"--crlUrl" }, description = "URL of the CRL (Certificate Revocation List) to check the revocation status of the signing certificate.")
	private String crlSourceUrl;

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
			"--report" }, description = "Type of validation report to generate (simpleReport, validationReport, none). Default: Both simpleReport and validationReport")
	private String reportType;

	@Option(names = { "-tl",
			"--tlSourceUrl" }, description = "URL or filepath of the Trusted List (TL) source to be used for signature verification and revocation data checking. Should point to an official EU TL or national TL. Optional.")
	private String tlSourceUrl;

	@Option(names = { "-aia",
			"--aiaSourceUrl" }, description = "URL of the Authority Information Access (AIA) source to be used for signature verification. Optional.")
	private String aiaSourceUrl;

	@Option(names = { "-ocsp",
			"--ocspSourceUrl" }, description = "URL of the Online Certificate Status Protocol (OCSP) source to be used for signature verification. Optional.")
	private String ocspSourceUrl;

	// TO-DO: Add the option to set "expected output" in which the user can specify
	// which output they want to get outputed in the CLI, e.g "Indication,
	// SubIndication, QualificationDetails, ..."

	private static String logFileName = null;

	@Override
	public void run() {

		// Check whether the user has specified an action (sign or verify) and throw an
		// error if neither or both actions are specified
		if ((verify && sign)) {
			logger.error(
					"No action specified. Please use -s or --sign to sign the input file, or -v or --verify to verify the signature of the input file. Only one action can be performed at a time.");
			throw new ApplicationException(
					"No action specified. Please use -s or --sign to sign the input file, or -v or --verify to verify the signature of the input file. Only one action can be performed at a time.");
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
			String logFileNameProperty = properties.getOrDefault("logFileName", "cades-sign");

			// Build the actual log file name with timestamp
			String timestamp = new java.text.SimpleDateFormat("yy-MM-dd-HH-mm-ss").format(new java.util.Date());
			logFileName = logDirProperty + "/" + logFileNameProperty + "-" + timestamp + "-0.log";

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

		// Options that do not yet work

		if (aiaSourceUrl != null && !aiaSourceUrl.isEmpty()) {
			throw new ApplicationException("Option -aia or --aiaSourceUrl is not yet implemented.");
		}

		if (ocspSourceUrl != null && !ocspSourceUrl.isEmpty()) {
			throw new ApplicationException("Option -ocsp or --ocspSourceUrl is not yet implemented.");
		}

		if (sign) {
			// Check whether the minimum required parameters for signing are provided and
			// throw an error if any of them are missing
			if (signatureLevel == null) {
				throw new ApplicationException("Signature level is not specified.");
			} else if (certPassword == null || certPassword.isEmpty()) {
				throw new ApplicationException("Certificate password is not specified.");
			} else if (certFile == null) {
				throw new ApplicationException("Certificate file is not specified.");
			} else {
				sign();
			}
		}

		if (verify) {
			verify();
		}
	}

	// Method to perform CAdES signature verification of the input file using the
	// specified parameters and generate a validation report
	public void verify() {

		logger.info("Starting CAdES signature verification process.");

		// Load the signed file and the original file as DSSDocument instances
		logger.debug(inputFile.getAbsolutePath());
		FileDocument fileToValidate = new FileDocument(inputFile);
		logger.debug("Loaded signed file for validation: " + inputFile.getAbsolutePath());

		// Initialize the certificate verifier for validation
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		logger.debug("Initialized certificate verifier for validation.");

		// Configure TrustedList source for revocation data checking (if provided)
		if (tlSourceUrl != null && !tlSourceUrl.isEmpty()) {
			configureTrustedList(certificateVerifier, tlSourceUrl);
		}

		/*
		 * // Configure the TL source if a TL source URL is provided by the user and set
		 * it as a trusted certificate source for validation
		 * if (tlSourceUrl != null && !tlSourceUrl.isEmpty()) {
		 * CommonsDataLoader dataLoader = new CommonsDataLoader();
		 * 
		 * // Set an instance of TrustAllStrategy to rely on the Trusted Lists content
		 * instead of the JVM trust store.
		 * dataLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);
		 */

		// Initialize the document validator for the signed file
		DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(fileToValidate);
		documentValidator.setCertificateVerifier(certificateVerifier);
		logger.debug("Initialized document validator for the signed file.");

		// Set the original document as detached content for validation
		if (originalFile != null && originalFile.exists()) {
			logger.debug("Original file provided. Setting it as detached content for validation: "
					+ originalFile.getAbsolutePath());
			List<DSSDocument> originalDocuments = new ArrayList<>();
			originalDocuments.add(new FileDocument(originalFile));
			documentValidator.setDetachedContents(originalDocuments);
		} else {
			logger.info("No original file provided for validation.");
		}

		// Set the evidence record document for validation if provided
		if (evidenceRecord != null && evidenceRecord.exists()) {
			logger.debug("Evidence record file provided. Setting it as detached evidence record for validation: "
					+ evidenceRecord.getAbsolutePath());
			logger.debug("TEST");
			List<DSSDocument> evidenceRecordDocuments = new ArrayList<>();
			evidenceRecordDocuments.add(new FileDocument(evidenceRecord));
			documentValidator.setDetachedEvidenceRecordDocuments(evidenceRecordDocuments);
		} else {
			logger.info("No evidence record file provided for validation.");
		}

		// Set the signing certificate for validation if provided
		if (signingCertificate != null && signingCertificate.exists()) {
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
		} else {
			logger.info("No signing certificate file provided for validation.");
		}

		// 7.4.8 HTML Doc: Set the token identifier provider to use for validation. This
		// makes the validation report more user friendly, by displaying tokens as human
		// readable names (AI-generated explanation)
		documentValidator.setTokenIdentifierProvider(
				true ? new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider());
		logger.debug("Set token identifier provider for validation.");

		// 7.4.9 HTML Doc: Set whether to include the semantics of the signature in the
		// validation process. Setting this to false will make the validation process
		// rely solely on the information provided in the signature and not on any
		// external information, such as the content of the signed file or the context
		// of the signature. This can be useful in cases where the semantics of the
		// signature are not relevant for validation or when you want to ensure that the
		// validation process is based only on the information contained within the
		// signature itself. However, it may also lead to less accurate validation
		// results if the semantics of the signature are important for determining its
		// validity. Depending on your specific use case and requirements, you may
		// choose to set this option to true or false. (AI-generated explanation)
		documentValidator.setIncludeSemantics(false);
		logger.debug("Set include semantics to false for validation.");

		// Load the validation policy from the provided file or use a default policy if
		// not provided
		logger.info(
				"---------------------------------------- START: Validation Policy ----------------------------------------");
		Reports finalReport = documentValidator.validateDocument(validationPolicy);
		logger.info(
				"---------------------------------------- END: Validation Policy ----------------------------------------");
		logger.info("CAdES signature validation process completed. Validation report generated.");

		// Create a baseName if the user has not specified an output file name, based on
		// the input file name and signature level
		if (outputFile == null || outputFile.isEmpty()) {
			logger.warn(
					"No output file specified for validation report. Generating default output file name based on input file.");
			outputFile = inputFile.getAbsolutePath();
			outputFile = outputFile.substring(0, outputFile.lastIndexOf("."));
			logger.debug("Base output file name generated: " + outputFile);
		}

		// check whether the user has specified a report type, if not, default to
		// generating all reports as to not get a null pointer exception when trying to
		// generate the report
		if (reportType == null || reportType.isEmpty()) {
			reportType = "fullReport";
		}

		// Generate the validation report based on the user-specified report type and
		// save it to the output file
		logger.debug("Generating validation report based on user-specified report type: " + reportType);
		switch (reportType) {
			// Generate the simple report if the user has specified "simpleReport" as the
			// report type
			case "simpleReport":
				logger.debug("Generating simple report for validation results.");
				outputFile += "_simple_report.xml";
				try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
					logger.debug("Writing simple report to file: " + outputFile);
					writer.write(finalReport.getXmlSimpleReport());
					logger.info("Simple report saved to: " + outputFile);
				} catch (IOException e) {
					logger.error("Error saving simple report: " + e.getMessage());
				}
				break;
			// Generate the validation report if the user has specified "validationReport"
			// as the report type
			case "validationReport":
				logger.debug("Generating validation report for validation results.");
				outputFile += "_validation_report.xml";
				try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
					logger.debug("Writing validation report to file: " + outputFile);
					writer.write(finalReport.getXmlValidationReport());
					logger.info("Validation report saved to: " + outputFile);
				} catch (IOException e) {
					logger.error("Error saving validation report: " + e.getMessage());
				}
				break;
			// Generate no report if the user has specified "none" as the report type
			case "none":
				logger.debug("No report will be generated as per user specification.");
				break;
			// Generate the full report (both simple report and validation report) if the
			// user has specified any other value as the report type or if the report type
			// is not specified
			default:
				logger.debug("Generating full report for validation results.");
				outputFile += "_full_report.xml";
				try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
					logger.debug("Writing full report to file: " + outputFile);
					writer.write("SimpleReport:\n" + finalReport.getXmlSimpleReport()
							+ "\n\nValidationReport:\n" + finalReport.getXmlValidationReport());
					logger.info("Full validation report saved to: " + outputFile);
				} catch (IOException e) {
					logger.error("Error saving full validation report: " + e.getMessage());
				}
		}

		// Log the indication and sub-indication from the simple report for the first
		// signature in the signed file
		logger.info("Indication: "
				+ finalReport.getSimpleReport().getIndication(finalReport.getSimpleReport().getFirstSignatureId()));
		logger.info("SubIndication: "
				+ finalReport.getSimpleReport().getSubIndication(finalReport.getSimpleReport().getFirstSignatureId()));
		logger.info("Validation report generation completed.");
	}

	// Method to perform CAdES signing of the input file using the specified
	// parameters and save the signed document to the output file
	public void sign() {

		// Define string constants for signature levels to avoid hardcoding the same
		// strings multiple times and to make the code more maintainable
		String cadesBaselineLT = "CAdES-BASELINE-LT";
		String cadesBaselineLTA = "CAdES-BASELINE-LTA";

		// Initialize variables for signature token and signer entry
		SignatureTokenConnection signatureToken = null;
		DSSPrivateKeyEntry signerEntry = null;
		DSSDocument signedDocument = null;

		// Phase 1: Load the input file, initialize the certificate verifier, set up the
		// CAdES service, and initialize the CAdES signature parameters.
		logger.info("Phase 1: 10% done");

		// Load the input file to be signed
		DSSDocument documentToSign = new FileDocument(inputFile);
		logger.debug("Loaded input file: " + inputFile.getAbsolutePath());

		// Initialize the certificate verifier
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		logger.debug("Initialized certificate verifier.");

		// Get the signature level as a string for use in multiple checks
		String signatureLevelString = signatureLevel.toString();
		logger.debug("Signature level specified: " + signatureLevelString);

		// Configure revocation sources for LT and LTA signatures
		if (signatureLevelString.equals(cadesBaselineLT) || signatureLevelString.equals(cadesBaselineLTA)) {
			try {
				// Add online CRL source for revocation checking
				OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
				certificateVerifier.setCrlSource(onlineCRLSource);
				logger.debug("Configured online CRL source for revocation data.");

				// Add AIA source for certificate chain completion
				CommonsDataLoader dataLoader = new CommonsDataLoader();
				AIASource aiaSource = new DefaultAIASource(dataLoader);
				certificateVerifier.setAIASource(aiaSource);
				logger.debug("Configured AIA source for certificate chain completion.");
			} catch (Exception e) {
				logger.warn("Could not configure revocation sources: " + e.getMessage());
			}
		}

		// Configure TrustedList source for revocation data checking (if provided)
		if (tlSourceUrl != null && !tlSourceUrl.isEmpty()) {
			configureTrustedList(certificateVerifier, tlSourceUrl);
			logger.debug("Configured Trusted List source for revocation data checking with URL: " + tlSourceUrl);
			logger.debug("Trusted List sources: " + certificateVerifier.getTrustedCertSources().getCertificates());
		}

		// Configure CRL source if provided by user
		if (crlSourceUrl != null && !crlSourceUrl.isEmpty()) {
			configureCRLSource(certificateVerifier, crlSourceUrl);
			logger.debug("Configured CRL source for revocation data checking with URL: " + crlSourceUrl);
			logger.debug("CRL sources: " + certificateVerifier.getCrlSource().toString());
		}

		// Initialize the CAdES service
		CAdESService cadesService = new CAdESService(certificateVerifier);
		logger.debug("Initialized CAdES service.");

		// Set up the CAdES signature parameters
		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		logger.debug("Created CAdES signature parameters.");

		// Phase 2: Configure the signature parameters
		logger.info("Phase 2: 30% done");

		try {
			// Set the digest algorithm
			parameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
			logger.debug("Set digest algorithm to: " + signatureAlgorithm.getDigestAlgorithm());
		} catch (Exception e) {
			logger.error("Error setting digest algorithm: " + e.getMessage());
			throw new ApplicationException("Failed to set digest algorithm.", e);
		}

		try {
			// Set the signature level
			parameters.setSignatureLevel(signatureLevel);
			logger.debug("Set signature level to: " + signatureLevel);
		} catch (Exception e) {
			logger.error("Error setting signature level: " + e.getMessage());
			throw new ApplicationException("Failed to set signature level.", e);
		}

		try {
			// Set the signature packaging
			parameters.setSignaturePackaging(signaturePackaging);
			logger.debug("Set signature packaging to: " + signaturePackaging);
		} catch (Exception e) {
			logger.error("Error setting signature packaging: " + e.getMessage());
			throw new ApplicationException("Failed to set signature packaging.", e);
		}

		try {
			CAdESTimestampParameters timestampParams = new CAdESTimestampParameters();
			cadesService.setTspSource(new OnlineTSPSource(tsaUrl));
			logger.debug("Configured Time Stamping Authority (TSA) with URL: " + tsaUrl);

			// Set the timestamp parameter for the -T level
			parameters.setSignatureTimestampParameters(timestampParams);

			// Set the timestamp parameter for the -LTA level
			parameters.setArchiveTimestampParameters(timestampParams);

		} catch (Exception e) {
			logger.error("Error configuring Time Stamping Authority (TSA): " + e.getMessage());
			throw new ApplicationException("Failed to configure TSA.", e);
		}

		try {
			parameters.setValidationDataEncapsulationStrategy(
					ValidationDataEncapsulationStrategy.ANY_VALIDATION_DATA_ONLY);
			logger.debug("Set validation data encapsulation strategy to: "
					+ parameters.getValidationDataEncapsulationStrategy());
		} catch (Exception e) {
			logger.error("Error setting validation data encapsulation strategy: " + e.getMessage());
			throw new ApplicationException("Failed to set validation data encapsulation strategy.", e);
		}

		try {
			KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(certFile, "PKCS12",
					certPassword.toCharArray());
			logger.debug("Set a total of " + keyStoreCertificateSource.getNumberOfCertificates()
					+ " certificate(s) from the PKCS12 file as a certificate source for validation.");

			CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
			// Add all certificates from the PKCS12 file
			for (CertificateToken cert : keyStoreCertificateSource.getCertificates()) {
				adjunctCertificateSource.addCertificate(cert);
			}
			certificateVerifier.setAdjunctCertSources(adjunctCertificateSource);
			logger.debug(
					"Added all certificates from PKCS12 file as adjunct certificate source for revocation data fetching.");

			CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
			trustedCertificateSource.importAsTrusted(keyStoreCertificateSource);
			logger.debug("Loaded PKCS12 keystore and imported certificates as trusted certificates for validation.");
			logger.info("Set a total of " + trustedCertificateSource.getNumberOfCertificates()
					+ " certificate(s) from the PKCS12 file as trusted certificates for validation.");
			logger.debug("Trusted certificates: " + trustedCertificateSource.getCertificates());
		} catch (Exception e) {
			logger.error("Error loading PKCS12 keystore: " + e.getMessage());
			throw new ApplicationException("Failed to load PKCS12 keystore.", e);
		}

		try {
			TLValidationJob job = new TLValidationJob();
			job.setOfflineDataLoader(offlineLoader());
		} catch (Exception e) {
			logger.warn("Could not set offline data loader for TLValidationJob: " + e.getMessage());
		}

		try {
			CertificateSource signingCertificateSource = new CommonCertificateSource();
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
		} catch (Exception e) {
			logger.warn("Could not load signing certificate from file: " + e.getMessage());
		}

		// Phase 3: Load the signing certificate and private key
		logger.info("Phase 3: 50% done");

		// Load the signing certificate and private key from the PKCS12 file
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

			// Extract the signing certificate from the signature token
			CertificateToken signingCertificate = signerEntry.getCertificate();
			logger.debug("Extracted signing certificate from signature token.");

			// Extract the certificate chain from the signature token
			CertificateToken[] chain = signerEntry.getCertificateChain();
			logger.debug(
					"Extracted certificate chain from signature token with " + chain.length + " certificate(s).");

			// Set the signing certificate
			parameters.setSigningCertificate(signingCertificate);
			logger.debug("Set signing certificate in signature parameters.");

			// Set the certificate chain
			parameters.setCertificateChain(chain);
			logger.debug("Set certificate chain in signature parameters.");

			// Add the certificate chain as an adjunct certificate source for revocation
			// checking
			// This is needed for LT level signatures to fetch revocation data
			if (signatureLevelString.equals(cadesBaselineLT) || signatureLevelString.equals(cadesBaselineLTA)) {
				CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
				for (CertificateToken cert : chain) {
					adjunctCertificateSource.addCertificate(cert);
				}
				certificateVerifier.setAdjunctCertSources(adjunctCertificateSource);
				logger.debug("Added certificate chain as adjunct certificate source for revocation data fetching.");
				logger.debug("Adjunct certificate sources: " + certificateVerifier.getAdjunctCertSources());
			}

		} catch (Exception e) {
			logger.error("Error loading signing certificate: " + e.getMessage());
			throw new ApplicationException("Failed to load signing certificate.", e);
		}

		// Phase 4: Obtain the data to be signed
		logger.info("Phase 4: 70% done");

		// Get the data to be signed from the CAdES service
		ToBeSigned toBeSigned = cadesService.getDataToSign(documentToSign, parameters);
		logger.debug("Obtained data to sign from CAdES service.");

		// Sign the data with the private key using the signature token
		SignatureValue signatureValue = signatureToken.sign(toBeSigned, signatureAlgorithm, signerEntry);
		logger.debug("Created signature value with algorithm " + signatureAlgorithm);

		logger.debug("--------------------------- START: Signature Parameters ---------------------------");
		logger.debug("These are the parameters used for signing: \n" + parameters.toString());
		logger.debug("--------------------------- END: Signature Parameters ---------------------------");

		// Phase 5: Sign and save the document
		logger.info("Phase 5: 90% done");

		try {
			// Sign the document using the CAdES service
			signedDocument = cadesService.signDocument(documentToSign, parameters, signatureValue);
			logger.debug("Signed the document using CAdES service.");
		} catch (Exception e) {
			// Check if the error is due to missing revocation data for untrusted chains
			String errorMsg = e.getMessage();
			if (errorMsg != null && errorMsg.contains("Revocation data is missing")
					&& errorMsg.contains("untrusted certificate chain")) {
				logger.error("Error signing the document: " + e.getMessage());
				logger.warn(
						"The certificate chain is not rooted in a trusted CA. For CAdES-BASELINE-LT/LTA signatures, " +
								"you must:");
				logger.warn(
						"Configure trusted lists or provide root certificates that the revocation sources can verify");
				throw new ApplicationException(
						"Failed to sign the document: Certificate chain is not in a trusted list. " +
								"Either use CAdES_BASELINE_T or provide trusted root certificates.",
						e);
			} else {
				logger.error("Error signing the document: " + e.getMessage());
				throw new ApplicationException("Failed to sign the document.", e);
			}
		}

		// If output file is not specified, save the signed document in the same
		// directory as the input file with a default name
		if (outputFile == null || outputFile.isEmpty()) {
			logger.warn("No output file specified. Generating default output file name based on input file.");

			String extension = null;
			if (signaturePackaging.toString().equals("ENVELOPING")) {
				extension = ".p7m";
			} else {
				extension = ".p7s";
			}

			outputFile = inputFile.getAbsolutePath();
			outputFile = outputFile.substring(0, outputFile.lastIndexOf("."));
			outputFile = outputFile + "-" + signatureLevel.toString() + extension;
		}

		// Save the signed document to the specified output file
		try {
			signedDocument.save(outputFile);
			logger.debug("Saved signed document to: " + outputFile);
		} catch (IOException e) {
			logger.error("Error saving the signed document: " + e.getMessage());
			throw new ApplicationException("Failed to save the signed document.", e);
		}

		logger.info("100% CAdES signing process completed successfully. Signed file saved at: " + outputFile);
	}

	// Helper method to check if the certificate bytes are in PEM format
	private static boolean isPem(byte[] string) {
		return Utils.startsWith(string, "-----".getBytes());
	}

	/**
	 * Configure the TrustedList (TL) for revocation data checking.
	 * This method sets up a TLValidationJob with the provided TL source URL or
	 * filepath.
	 * The TrustedListsCertificateSource is then added to the certificate verifier.
	 * 
	 * @param certificateVerifier The certificate verifier to add the TL source to
	 * @param tlSourceUrl         The URL or filepath of the Trusted List
	 */
	private void configureTrustedList(CertificateVerifier certificateVerifier, String tlSourceUrl) {
		if (tlSourceUrl == null || tlSourceUrl.isEmpty()) {
			logger.debug("No TrustedList source provided. Skipping TL configuration.");
			return;
		}

		try {
			logger.info("Configuring TrustedList source: " + tlSourceUrl);

			// Convert local filepath to file:// URL if needed
			String tlUrl = convertToFileUrl(tlSourceUrl);
			logger.debug("Converted TL source to URL format: " + tlUrl);

			// Create and configure the TLValidationJob
			TLValidationJob tlValidationJob = new TLValidationJob();

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
			try {
				CommonsDataLoader dataLoader = new CommonsDataLoader();
				FileCacheDataLoader cachedDataLoader = new FileCacheDataLoader(dataLoader);
				cachedDataLoader.setFileCacheDirectory(getTLCacheDirectory());
				cachedDataLoader.setCacheExpirationTime(-1); // cache never expires

				tlValidationJob.setOnlineDataLoader(cachedDataLoader);
				logger.debug("Set online data loader with cache for TLValidationJob.");

				// Also set offline loader for offline validation
				tlValidationJob.setOfflineDataLoader(offlineLoader());
				logger.debug("Set offline data loader for TLValidationJob.");
			} catch (Exception e) {
				logger.warn("Could not configure data loaders: " + e.getMessage());
				// Try with just online loader
				CommonsDataLoader dataLoader = new CommonsDataLoader();
				FileCacheDataLoader cachedDataLoader = new FileCacheDataLoader(dataLoader);
				cachedDataLoader.setFileCacheDirectory(getTLCacheDirectory());
				tlValidationJob.setOnlineDataLoader(cachedDataLoader);
				logger.debug("Set online data loader for TLValidationJob.");
			}

			// Refresh and load the TrustedList
			tlValidationJob.onlineRefresh();
			logger.info("TrustedList refresh completed. Loaded "
					+ trustedListsCertificateSource.getNumberOfCertificates() + " certificate(s).");

			// Add the TrustedListsCertificateSource to the certificate verifier
			certificateVerifier.setTrustedCertSources(trustedListsCertificateSource);
			logger.info("TrustedListsCertificateSource added to certificate verifier for revocation data checking.");

		} catch (Exception e) {
			logger.error("Error configuring TrustedList: " + e.getMessage());
			logger.warn(
					"TrustedList configuration failed. Continuing without TL. Revocation checking may fail for untrusted chains.");
		}
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

	public DSSCacheFileLoader offlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(-1); // negative value means cache never expires
		offlineFileLoader.setDataLoader(new IgnoreDataLoader());
		offlineFileLoader.setFileCacheDirectory(getTLCacheDirectory());
		return offlineFileLoader;
	}

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

	private void configureCRLSource(CertificateVerifier certificateVerifier, String crlSourcePath) {
		if (crlSourcePath == null || crlSourcePath.isEmpty()) {
			return;
		}

		try {
			File crlFile = new File(crlSourcePath);

			if (crlFile.exists() && crlFile.isFile()) {
				// Load CRL from DER format file
				logger.info("Loading CRL from file: " + crlFile.getAbsolutePath());

				byte[] crlBytes = Files.readAllBytes(crlFile.toPath());

				// Create CRL certificate source
				CommonCertificateSource crlSource = new CommonCertificateSource();

				// Parse CRL and add to verifier
				certificateVerifier.setAdjunctCertSources(crlSource);
				logger.info("CRL loaded successfully from: " + crlFile.getAbsolutePath());
			}
		} catch (Exception e) {
			logger.warn("Could not configure CRL source: " + e.getMessage());
			throw new ApplicationException("Failed to configure CRL source.", e);
		}
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
