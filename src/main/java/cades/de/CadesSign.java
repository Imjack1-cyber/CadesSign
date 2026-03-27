package cades.de;

import cades.de.exception.ApplicationException;

import java.io.IOException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.security.KeyStore.PasswordProtection;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.Handler;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

import eu.europa.esig.dss.validation.DocumentValidator;

@Command(name = "cades-sign", version = "CadesSign 1.0", description = "CadesSign - A tool for signing files using CAdES signatures.", mixinStandardHelpOptions = true)
public class CadesSign implements Runnable {

	Logger logger = Logger.getLogger(getClass().getName());

	// Common options
	@Option(names = { "-i",
			"--input" }, description = "Path to the input file to be signed or verified.", required = true)
	private File inputFile;

	@Option(names = { "-ll",
			"--logLevel" }, description = "Logging level (e.g., SEVERE, WARNING, INFO, FINE). Default: INFO", defaultValue = "INFO")
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

	/*
	 * TO-DO: Add options for CRL and OCSP sources to check the revocation status of
	 * the signing certificate.
	 * 
	 * @Option(names = { "-crl",
	 * "--crlUrl" }, description =
	 * "URL of the CRL (Certificate Revocation List) to check the revocation status of the signing certificate."
	 * )
	 * private String crlUrl;
	 * 
	 * @Option(names = { "-ocsp",
	 * "--ocspUrl" }, description =
	 * "URL of the OCSP (Online Certificate Status Protocol) responder to check the revocation status of the signing certificate."
	 * )
	 * private String ocspUrl;
	 */

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

	// TO-DO: Add the option to set "expected output" in which the user can specify
	// which output they want to get outputed in the CLI, e.g "Indication,
	// SubIndication, QualificationDetails, ..."

	@Override
	public void run() {

		// Check whether the user has specified an action (sign or verify) and throw an
		// error if neither or both actions are specified
		if ((verify == false && sign == false) || (verify == true && sign == true)) {
			logger.severe(
					"No action specified. Please use -s or --sign to sign the input file, or -v or --verify to verify the signature of the input file. Only one action can be performed at a time.");
			throw new ApplicationException(
					"No action specified. Please use -s or --sign to sign the input file, or -v or --verify to verify the signature of the input file. Only one action can be performed at a time.");
		}

		// Configure logging level based on user input
		try {
			logger.setLevel(Level.parse(logLevel));

			// Configure all handlers of this logger to the specified log level
			for (Handler handler : logger.getHandlers()) {
				handler.setLevel(Level.parse(logLevel));
			}
			// Also configure the root logger and its handlers
			Logger rootLogger = Logger.getLogger("");
			rootLogger.setLevel(Level.parse(logLevel));
			for (Handler handler : rootLogger.getHandlers()) {
				handler.setLevel(Level.parse(logLevel));
			}
			logger.info("Starting CAdES process with log level: " + logger.getLevel().toString());
		} catch (IllegalArgumentException e) {
			logger.warning("Invalid log level specified: " + logLevel + ". Defaulting to INFO level.");
		}

		if (sign) {
			// Check whether the minimum required parameters for signing are provided and
			// throw an error if any of them are missing
			if (signatureLevel.toString().isEmpty()) {
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
		logger.fine("TEST");
		logger.fine(inputFile.getAbsolutePath());
		FileDocument fileToValidate = new FileDocument(inputFile);
		logger.fine("Loaded signed file for validation: " + inputFile.getAbsolutePath());

		// Initialize the certificate verifier for validation
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		logger.fine("Initialized certificate verifier for validation.");

		// Initialize the document validator for the signed file
		DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(fileToValidate);
		documentValidator.setCertificateVerifier(certificateVerifier);
		logger.fine("Initialized document validator for the signed file.");

		// Set the original document as detached content for validation
		if (originalFile != null) {
			logger.fine("Original file provided. Setting it as detached content for validation: "
					+ originalFile.getAbsolutePath());
			List<DSSDocument> originalDocuments = new ArrayList<>();
			originalDocuments.add(new FileDocument(originalFile));
			documentValidator.setDetachedContents(originalDocuments);
		}

		// Set the evidence record document for validation if provided
		if (evidenceRecord != null) {
			logger.fine("Evidence record file provided. Setting it as detached evidence record for validation: "
					+ evidenceRecord.getAbsolutePath());
			List<DSSDocument> evidenceRecordDocuments = new ArrayList<>();
			evidenceRecordDocuments.add(new FileDocument(evidenceRecord));
			documentValidator.setDetachedEvidenceRecordDocuments(evidenceRecordDocuments);
		}

		// Set the signing certificate for validation if provided
		if (signingCertificate != null) {
			// Load the signing certificate from the provided file and set it as a
			// certificate source for validation
			logger.fine("Signing certificate file provided. Loading it for validation: "
					+ signingCertificate.getAbsolutePath());
			CommonCertificateSource signingCertificateSource = new CommonCertificateSource();
			CertificateToken signingCertificateToken = null;

			// Check if the certificate file is in PEM format or Base64 encoded, and load it
			// accordingly
			byte[] certificateBytes = DSSUtils.toByteArray(signingCertificate);
			String certificateBytesString = new String(certificateBytes);
			if (!isPem(certificateBytes) && Utils.isBase64Encoded(certificateBytesString)) {
				signingCertificateToken = DSSUtils.loadCertificateFromBase64EncodedString(certificateBytesString);
			}

			// If the certificate is not in PEM format or Base64 encoded, try to load it as
			// a regular certificate file
			signingCertificateToken = DSSUtils.loadCertificate(certificateBytes);
			signingCertificateSource.addCertificate(signingCertificateToken);
			documentValidator.setSigningCertificateSource(signingCertificateSource);
		}

		// TO-DO: Find out what this means and how it works
		documentValidator.setTokenIdentifierProvider(
				true ? new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider());
		logger.fine("Set token identifier provider for validation.");

		// TO-DO: Find out what this means and how it works
		documentValidator.setIncludeSemantics(false);
		logger.fine("Set include semantics to false for validation.");

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
			logger.warning(
					"No output file specified for validation report. Generating default output file name based on input file.");
			outputFile = inputFile.getAbsolutePath();
			outputFile = outputFile.substring(0, outputFile.lastIndexOf("."));
			logger.fine("Base output file name generated: " + outputFile);
		}

		// check whether the user has specified a report type, if not, default to
		// generating all reports as to not get a null pointer exception when trying to
		// generate the report
		if (reportType == null || reportType.isEmpty()) {
			reportType = "fullReport";
		}

		// Generate the validation report based on the user-specified report type and
		// save it to the output file
		logger.fine("Generating validation report based on user-specified report type: " + reportType);
		switch (reportType) {
			// Generate the simple report if the user has specified "simpleReport" as the
			// report type
			case "simpleReport":
				logger.fine("Generating simple report for validation results.");
				outputFile += "_simple_report.xml";
				try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
					logger.fine("Writing simple report to file: " + outputFile);
					writer.write(finalReport.getXmlSimpleReport().toString());
					logger.info("Simple report saved to: " + outputFile);
				} catch (IOException e) {
					logger.severe("Error saving simple report: " + e.getMessage());
				}
				break;
			// Generate the validation report if the user has specified "validationReport"
			// as the report type
			case "validationReport":
				logger.fine("Generating validation report for validation results.");
				outputFile += "_validation_report.xml";
				try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
					logger.fine("Writing validation report to file: " + outputFile);
					writer.write(finalReport.getXmlValidationReport().toString());
					logger.info("Validation report saved to: " + outputFile);
				} catch (IOException e) {
					logger.severe("Error saving validation report: " + e.getMessage());
				}
				break;
			// Generate no report if the user has specified "none" as the report type
			case "none":
				logger.fine("No report will be generated as per user specification.");
				break;
			// Generate the full report (both simple report and validation report) if the
			// user has specified any other value as the report type or if the report type
			// is not specified
			default:
				logger.fine("Generating full report for validation results.");
				outputFile += "_full_report.xml";
				try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
					logger.fine("Writing full report to file: " + outputFile);
					writer.write("SimpleReport:\n" + finalReport.getXmlSimpleReport().toString()
							+ "\n\nValidationReport:\n" + finalReport.getXmlValidationReport().toString());
					logger.info("Full validation report saved to: " + outputFile);
				} catch (IOException e) {
					logger.severe("Error saving full validation report: " + e.getMessage());
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

		// Initialize variables for signature token and signer entry
		SignatureTokenConnection signatureToken = null;
		DSSPrivateKeyEntry signerEntry = null;
		DSSDocument signedDocument = null;

		// Phase 1: Load the input file, initialize the certificate verifier, set up the
		// CAdES service, and initialize the CAdES signature parameters.
		logger.info("Phase 1: 10% done");

		// Load the input file to be signed
		DSSDocument documentToSign = new FileDocument(inputFile);
		logger.fine("Loaded input file: " + inputFile.getAbsolutePath());

		// Initialize the certificate verifier
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		logger.fine("Initialized certificate verifier.");

		// Initialize the CAdES service
		CAdESService cadesService = new CAdESService(certificateVerifier);
		logger.fine("Initialized CAdES service.");

		// Set up the CAdES signature parameters
		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		logger.fine("Created CAdES signature parameters.");

		// Phase 2: Configure the signature parameters
		logger.info("Phase 2: 30% done");

		try {
			// Set the digest algorithm
			parameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
			logger.fine("Set digest algorithm to: " + signatureAlgorithm.getDigestAlgorithm());
		} catch (Exception e) {
			logger.severe("Error setting digest algorithm: " + e.getMessage());
			throw new ApplicationException("Failed to set digest algorithm.", e);
		}

		try {
			// Set the signature level
			parameters.setSignatureLevel(signatureLevel);
			logger.fine("Set signature level to: " + signatureLevel);
		} catch (Exception e) {
			logger.severe("Error setting signature level: " + e.getMessage());
			throw new ApplicationException("Failed to set signature level.", e);
		}

		try {
			// Set the signature packaging
			parameters.setSignaturePackaging(signaturePackaging);
			logger.fine("Set signature packaging to: " + signaturePackaging);
		} catch (Exception e) {
			logger.severe("Error setting signature packaging: " + e.getMessage());
			throw new ApplicationException("Failed to set signature packaging.", e);
		}

		String signatureLevelString = signatureLevel.toString();
		if (signatureLevelString.equals("CAdES-BASELINE-T")
				|| signatureLevelString.equals("CAdES-BASELINE-LT")
				|| signatureLevelString.equals("CAdES-BASELINE-LTA")) {
			if (tsaUrl == null || tsaUrl.isEmpty()) {
				logger.severe("Current signature level " + signatureLevelString);
				throw new ApplicationException(
						"TSA URL must be provided for signature levels that include timestamps (Baseline-T, Baseline-LT, Baseline-LTA). Please provide a valid TSA URL using the -t or --tsaUrl option.");
			}
		}

		// Configure TSA if URL is provided
		try {
			CAdESTimestampParameters timestampParams = new CAdESTimestampParameters();
			cadesService.setTspSource(new OnlineTSPSource(tsaUrl));
			logger.fine("Configured Time Stamping Authority (TSA) with URL: " + tsaUrl);

			// For Baseline-B (includes content timestamp):
			parameters.setContentTimestampParameters(timestampParams);

			// For Baseline-T (includes timestamp):
			parameters.setSignatureTimestampParameters(timestampParams);

			// Or for Baseline-LTA (timestamp + archive data):
			parameters.setArchiveTimestampParameters(timestampParams);
		} catch (Exception e) {
			logger.severe("Error configuring Time Stamping Authority (TSA): " + e.getMessage());
			throw new ApplicationException("Failed to configure TSA.", e);
		}

		// Phase 3: Load the signing certificate and private key
		logger.info("Phase 3: 50% done");

		// Load the signing certificate and private key from the PKCS12 file
		try {
			// Load the PKCS12 keystore
			signatureToken = new Pkcs12SignatureToken(certFile, new PasswordProtection(certPassword.toCharArray()));
			logger.fine("Initialized PKCS12 signature token with keystore: " + certFile.getAbsolutePath());

			// Extract the private key entry from the signature token
			List<DSSPrivateKeyEntry> privateKeyEntries = signatureToken.getKeys();
			logger.fine(
					"Extracted " + privateKeyEntries.size() + " private key entry(ies) from the signature token.");

			// Using the first private key entry for signing
			// TO-DO: Add an option to select a specific private key entry if there are
			// multiple entries in the PKCS12 file.
			signerEntry = privateKeyEntries.get(0);
			logger.fine("Selected private key entry for signing.");

			// Extract the signing certificate from the signature token
			CertificateToken signingCertificate = signerEntry.getCertificate();
			logger.fine("Extracted signing certificate from signature token.");

			// Extract the certificate chain from the signature token
			CertificateToken[] chain = signerEntry.getCertificateChain();
			logger.fine(
					"Extracted certificate chain from signature token with " + chain.length + " certificate(s).");

			// Set the signing certificate
			parameters.setSigningCertificate(signingCertificate);
			logger.fine("Set signing certificate in signature parameters.");

			// Set the certificate chain
			parameters.setCertificateChain(chain);
			logger.fine("Set certificate chain in signature parameters.");

		} catch (Exception e) {
			logger.severe("Error loading signing certificate: " + e.getMessage());
			throw new ApplicationException("Failed to load signing certificate.", e);
		}

		// Phase 4: Obtain the data to be signed
		logger.info("Phase 4: 70% done");

		// Get the data to be signed from the CAdES service
		ToBeSigned toBeSigned = cadesService.getDataToSign(documentToSign, parameters);
		logger.fine("Obtained data to sign from CAdES service.");

		// Sign the data with the private key using the signature token
		SignatureValue signatureValue = signatureToken.sign(toBeSigned, signatureAlgorithm, signerEntry);
		logger.fine("Created signature value with algorithm " + signatureAlgorithm);

		logger.fine("--------------------------- START: Signature Parameters ---------------------------");
		logger.fine("These are the parameters used for signing: \n" + parameters.toString());
		logger.fine("--------------------------- END: Signature Parameters ---------------------------");

		// Phase 5: Sign and save the document
		logger.info("Phase 5: 90% done");

		try {
			// Sign the document using the CAdES service
			signedDocument = cadesService.signDocument(documentToSign, parameters, signatureValue);
			logger.fine("Signed the document using CAdES service.");
		} catch (Exception e) {
			logger.severe("Error signing the document: " + e.getMessage());
			throw new ApplicationException("Failed to sign the document.", e);
		}

		// If output file is not specified, save the signed document in the same
		// directory as the input file with a default name
		if (outputFile == null || outputFile.isEmpty()) {
			logger.warning("No output file specified. Generating default output file name based on input file.");

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
			logger.fine("Saved signed document to: " + outputFile);
		} catch (IOException e) {
			logger.severe("Error saving the signed document: " + e.getMessage());
			throw new ApplicationException("Failed to save the signed document.", e);
		}

		logger.info("100% CAdES signing process completed successfully. Signed file saved at: " + outputFile);
	}

	// Helper method to check if the certificate bytes are in PEM format
	private static boolean isPem(byte[] string) {
		return Utils.startsWith(string, "-----".getBytes());
	}

	public static void main(String[] args) {
		int exitCode = new picocli.CommandLine(new CadesSign()).execute(args);
		System.exit(exitCode);
	}
}
