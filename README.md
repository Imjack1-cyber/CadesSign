# CadesSign

A command-line tool for signing and verifying files using **CAdES (CMS Advanced Electronic Signatures)**.

CadesSign integrates the DSS (Digital Signature Service) library to provide secure digital signing capabilities, supporting advanced signature levels, timestamps, and various validation policies.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Options](#command-options)

---

## Installation

### Prerequisites

- **Java 12 or higher**
- **Maven 3.6 or higher**

### Building the Project

1. Clone or navigate to the project directory:

   ```bash
   cd CadesSign
   ```

2. Compile the project using Maven:

   ```bash
   mvn clean package
   ```

   This will create an executable JAR file in the `target/` directory.

3. Verify the build was successful:

   ```bash
   java -jar target/cades-sign-1.0.0.jar --version
   ```

---

## Quick Start

```bash
java -jar target/cades-sign-1.0.0.jar [-a=<signatureAlgorithm>] [-aj=<adjunctCertificates>]
                  [-c=<certFile>] [-cs=<cryptographicSuite>]
                  [-er=<evidenceRecord>] -i=<inputFile> [-l=<signatureLevel>]
                  [-ll=<logLevel>] [-o=<outputFile>]
                  [--originalFile=<originalFile>] [-p=<certPassword>]
                  [-P=<signaturePackaging>] [-r=<reportType>]
                  [-sg=<signingCertificate>] [-t=<tsaUrl>]
                  [-vp=<validationPolicy>]
```

This generates a validation report showing signature status and chain of trust.

---

## Command Options

### Required Options (for Signing)

| Option | Short | Description | Default |
| ------ | ----- | ----------- | ------- |
| `--input` | `-i` | Path to the input file to be signed or verified | null |
| `--sign` | `-s` | Enable signing mode (use without value) | false |
| `--cert` | `-c` | Path to PKCS12 certificate file (.p12 or .pfx) | null |
| `--password` | `-p` | Password for the PKCS12 file | null |
| `--signatureLevel` | `-l` | Signature level (CAdES_BASELINE_B, CAdES_BASELINE_T, CAdES_BASELINE_LT) | null |

### Optional Signing Options

| Option | Short | Description | Default |
| ------ | ----- | ----------- | ------- |
| `--packaging` | `-P` | Signature type (ENVELOPING, DETACHED) | ENVELOPING |
| `--algorithm` | `-a` | Signature algorithm (RSA_SHA256, ECDSA_SHA256) | RSA_SHA256 |
| `--output` | `-o` | Output file path | Auto-generated |
| `--tsaUrl` | `-t` | Time Stamping Authority URL | null |

### Required Verification Options

| Option | Short | Description | Default |
| ------ | ----- | ----------- | ------- |
| `--verify` | `-v` | Enable verification mode (use without value) | false |
| `--input` | `-i` | Path to the input file to be signed or verified | null |

### Optional Verification Options

| Option | Short | Description | Default |
| ------ | ----- | ----------- | ------- |
| `--report` | `-r` | Report type (simpleReport, validationReport, none) | both |
| `--signingCertificate` | `-sg` | Path to signing certificate file | auto |
| `--validationPolicy` | `-vp` | Validation policy (PKIX, CAdES) | auto |
| `--cryptographicSuite` | `-cs` | Cryptographic suite (BCPQC, NIST) | auto |
| `--adjunctCertificates` | `-aj` | Path to adjunct certificates file | auto |
| `--evidenceRecord` | `-er` | Path to evidence record file | auto |

### Utility Options

| Option | Short | Description | Default |
| ------ | ----- | ----------- | ------- |
| `--logLevel` | `-ll` | Logging verbosity (SEVERE, WARNING, INFO, FINE) | INFO |
| `--help` | `-h` | Show help message | |
| `--version` | `-V` | Show version information | |

---

## Signature Levels Explained

- **CAdES_BASELINE_B**: Basic signature (timestamp not included)
- **CAdES_BASELINE_T**: With timestamp (recommended for most use cases)
- **CAdES_BASELINE_LT**: Long-term with full validation data (best for archival)

---

## Support

For detailed documentation on DSS and CAdES standards, visit:

- [DSS Java Documentation](<https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/index.html>)
- [CAdES Standard (ETSI TS 101 733)](<https://www.etsi.org/standards#page=1&search=101 733>)
