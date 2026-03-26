package cades.de;

import cades.de.exception.ApplicationException;

import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.util.List;
import java.security.KeyStore.PasswordProtection;
import java.util.Date;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.Handler;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

@Command(name = "cades-sign", version = "CadesSign 1.0", description = "CadesSign - A tool for signing files using CAdES signatures.", mixinStandardHelpOptions = true)
public class CadesSign implements Runnable {

	Logger logger = Logger.getLogger(getClass().getName());

	@Option(names = { "-s",
			"--sign" }, description = "Sign the input file using CAdES signature with the specified parameters.", defaultValue = "false")
	private boolean sign;

	@Option(names = { "-v",
			"--verify" }, description = "Verify the signature of the input file.", defaultValue = "false")
	private boolean verify;

	@Option(names = { "-i", "--input" }, description = "Path to the input file to be signed.", required = true)
	private File inputFile;

	@Option(names = { "-o",
			"--output" }, description = "Path to the output file where the signed data will be saved.")
	private String outputFile;

	@Option(names = { "-c",
			"--cert" }, description = "Path to the pkcs12 file including the certificate and private key (e.g., .p12, .pfx) used for signing.", required = true)
	private File certFile;

	@Option(names = { "-p", "--password" }, description = "Password for the pkcs12 file.", required = true)
	private String certPassword;

	@Option(names = { "-t",
			"--tsaUrl" }, description = "URL of the Time Stamping Authority (TSA) to include a timestamp in the signature.")
	private String tsaUrl;

	@Option(names = { "-l",
			"--signatureLevel" }, description = "CAdES signature level (e.g., CAdES_BASELINE_B, CAdES_BASELINE_T, CAdES_BASELINE_LT). Default: CAdES_BASELINE_LT", required = true)
	private SignatureLevel signatureLevel;

	@Option(names = { "-P",
			"--packaging" }, description = "Signature packaging type (ENVELOPING, DETACHED). Default: ENVELOPING", defaultValue = "ENVELOPING")
	private SignaturePackaging signaturePackaging;

	@Option(names = { "-a",
			"--algorithm" }, description = "Signature algorithm (e.g., RSA_SHA256, ECDSA_SHA256). Default: RSA_SHA256", defaultValue = "RSA_SHA256")
	private SignatureAlgorithm signatureAlgorithm;

	@Option(names = { "-ll",
			"--logLevel" }, description = "Logging level (e.g., SEVERE, WARNING, INFO, FINE). Default: INFO", defaultValue = "INFO")
	private String logLevel;

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

	@Override
	public void run() {

		// Check whether the user has specified an action (sign or verify) and throw an
		// error if neither or both actions are specified
		if ((verify == false && sign == false) || (verify == true && sign == true)) {
			logger.severe(
					"No action specified. Please use -s or --sign to sign the input file, or -v or --verify to verify the signature of the input file.");
			throw new ApplicationException(
					"No action specified. Please use -s or --sign to sign the input file, or -v or --verify to verify the signature of the input file.");
		}

		if (sign) {
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
				logger.info("Starting CAdES signing process with log level: " + logger.getLevel().toString());
			} catch (IllegalArgumentException e) {
				logger.warning("Invalid log level specified: " + logLevel + ". Defaulting to INFO level.");
			}

			// Initialize variables for signature token and signer entry
			SignatureTokenConnection signatureToken = null;
			DSSPrivateKeyEntry signerEntry = null;

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

			// Set the digest algorithm
			parameters.setDigestAlgorithm(signatureAlgorithm.getDigestAlgorithm());
			logger.fine("Set digest algorithm to: " + signatureAlgorithm.getDigestAlgorithm());

			// Set the signature level
			parameters.setSignatureLevel(signatureLevel);
			logger.fine("Set signature level to: " + signatureLevel);

			// Set the signature packaging
			parameters.setSignaturePackaging(signaturePackaging);
			logger.fine("Set signature packaging to: " + signaturePackaging);

			// Configure TSA if URL is provided
			if (tsaUrl != null && !tsaUrl.isEmpty()) {
				CAdESTimestampParameters timestampParams = new CAdESTimestampParameters();
				cadesService.setTspSource(new OnlineTSPSource(tsaUrl));
				logger.fine("Configured Time Stamping Authority (TSA) with URL: " + tsaUrl);

				// For Baseline-B (includes content timestamp):
				parameters.setContentTimestampParameters(timestampParams);

				// For Baseline-T (includes timestamp):
				parameters.setSignatureTimestampParameters(timestampParams);

				// Or for Baseline-LTA (timestamp + archive data):
				parameters.setArchiveTimestampParameters(timestampParams);
			} else {
				logger.warning("No TSA URL provided. Signature will not include a timestamp.");
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

			// Sign the document using the CAdES service
			DSSDocument signedDocument = cadesService.signDocument(documentToSign, parameters, signatureValue);
			logger.fine("Signed the document using CAdES service.");

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

		if (verify) {
			throw new ApplicationException("Verification is not implemented.");
		}
	}

	public static void main(String[] args) {
		int exitCode = new picocli.CommandLine(new CadesSign()).execute(args);
		System.exit(exitCode);
	}
}
