# CadesSign

A command-line tool for signing and verifying files using **CAdES (CMS Advanced Electronic Signatures)**.

CadesSign integrates the DSS (Digital Signature Service) library to provide secure digital signing capabilities, supporting advanced signature levels, timestamps, revocation checking, and trusted list validation.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Example](#example)
- [Signing Files](#signing-files)
- [Verifying Signatures](#verifying-signatures)
- [Command Options](#command-options)
- [Signature Levels Explained](#signature-levels-explained)
- [Support](#support)

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
   java -jar target/cades-sign-1.0.0.jar --help
   ```

---

## Quick Start

### Basic Signing

```bash
java -jar target/cades-sign-1.0.0.jar -s -i <input-file> -c <keystore.p12> -p <password> -l <signatureLevel> -t <tsa-url>
```

### Basic Verification

```bash
java -jar target/cades-sign-1.0.0.jar -v -i <signed-file>
```

---

## Example

```bash
   ./scripts/generate_cert_chain.sh; /
   mvn clean package; /
   java -jar target/cades-sign-1.0.0.jar   -i "pom.xml"   -c "keystore/keystore.p12"   -p "1234"   -l "CAdES_BASELINE_T"   -a "RSA_SHA256"   -t "https://freetsa.org/tsr"   -tl "unified_trustlist.xml"  -ll "DEBUG" -s; /
   java -jar target/cades-sign-1.0.0.jar -i "pom-CAdES-BASELINE-T.p7m" -v; 
```

---

## Signing Files

To sign a file with CAdES, you must provide:

1. **Input file** (`-i, --input`): The file to be signed
2. **Certificate** (`-c, --cert`): PKCS12/PFX file containing the signing certificate and private key
3. **Password** (`-p, --password`): Password to unlock the PKCS12 file
4. **Signature Level** (`-l, --signatureLevel`): CAdES_BASELINE_B, CAdES_BASELINE_T, or CAdES_BASELINE_LT
5. **TSA URL** (`-t, --tsaUrl`): Time Stamping Authority URL (required for BASELINE_T and higher)

### Example sign

```bash
java -jar target/cades-sign-1.0.0.jar \
  -s \
  -i pom.xml \
  -c keystore.p12 \
  -p 1234 \
  -l CAdES_BASELINE_T \
  -a RSA_SHA256 \
  -t https://freetsa.org/tsr \
  -tl unified_trustlist.xml
```

---

## Verifying Signatures

To verify a signed file, provide:

1. **Input file** (`-i, --input`): The signed file to verify
2. **Optional**: Trusted List, validation policy, and other verification sources

### Example verify

```bash
java -jar target/cades-sign-1.0.0.jar \
  -v \
  -i pom-CAdES_BASELINE_T.p7m \
  -tl unified_trustlist.xml \
  -r simpleReport
```

---

## Command Options

### Common Options

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--input` | `-i` | Path to the input file to be signed or verified | — | **Yes** |
| `--logLevel` | `-ll` | Logging level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL) | INFO | No |
| `--help` | `-h` | Show help message | — | No |
| `--version` | `-V` | Print version information and exit | — | No |

### Signing Mode Options

#### Core Signing

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--sign` | `-s` | Enable signing mode | false | Required with `-c`, `-p` |
| `--cert` | `-c` | Path to PKCS12 file (.p12, .pfx) | — | Yes if `-s` used |
| `--password` | `-p` | Password for the PKCS12 file | — | Yes if `-s` used |
| `--signatureLevel` | `-l` | Signature level (CAdES_BASELINE_B, CAdES_BASELINE_T, CAdES_BASELINE_LT) | — | No |

#### Signature Configuration

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--algorithm` | `-a` | Signature algorithm (RSA_SHA256, RSA_SHA512) | RSA_SHA256 | No |
| `--packaging` | `-P` | Signature packaging (ENVELOPING, DETACHED) | ENVELOPING | No |
| `--output` | `-o` | Output file path | Auto-generated | No |

#### Timestamp & Revocation

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--tsaUrl` | `-t` | Time Stamping Authority URL | — | Required for BASELINE_T+ |
| `--intermediateCrlUrl` | `-iCrl` | Intermediate CRL for revocation checking | — | No |
| `--rootCrlUrl` | `-rCrl` | Root CRL for revocation checking | — | No |
| `--tsaRootCrlUrl` | `-tRCrl` | TSA root CRL for BASELINE_T and higher | — | No |

#### Trust & Validation Sources

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--tlSourceUrl` | `-tl` | Trusted List (TL) source URL or filepath | — | No |
| `--trustAnchorAlias` | `-ta` | Alias of certificate from PKCS12 to use as trusted anchor | — | No |

### Verification Mode Options

#### Core Verification

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--verify` | `-v` | Enable verification mode | false | No |

#### Verification Sources

| Option | Short | Description | Default | Required |
| ------ | ----- | ----------- | ------- | -------- |
| `--report` | `-r` | Report type (simpleReport, validationReport, none) | Both | No |
| `--originalFile` | — | Original file to include with DETACHED packaging | — | No |
| `--tlSourceUrl` | `-tl` | Trusted List (TL) source URL or filepath | — | No |
| `--validationPolicy` | `-vp` | Validation policy file (XML) | — | No |
| `--cryptographicSuite` | `-cs` | Cryptographic suite file (XML) | — | No |
| `--signingCertificate` | `-sg` | Signing certificate file | — | No |
| `--adjunctCertificates` | `-aj` | Adjunct certificates file | — | No |
| `--evidenceRecord` | `-er` | Evidence record file | — | No |
| `--aiaSourceUrl` | `-aia` | Authority Information Access (AIA) source URL | — | No |
| `--ocspSourceUrl` | `-ocsp` | Online Certificate Status Protocol (OCSP) source URL | — | No |

---

## Signature Levels Explained

- **CAdES_BASELINE_B**: Basic signature with no timestamp. Provides origin authentication but no proof of signature creation time.

- **CAdES_BASELINE_T**: Signature with timestamp from a Time Stamping Authority (TSA).  Provides cryptographic proof of creation time.

- **CAdES_BASELINE_LT**: Long-term signature with embedded revocation data (CRL/OCSP).  Requires timestamp, revocation information, and trusted list.

---

## Support

For detailed documentation on DSS and CAdES standards, visit:

- [DSS Java Documentation](<https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/index.html>)
- [CAdES Standard (ETSI TS 101 733)](<https://www.etsi.org/standards#page=1&search=101 733>)
- [ETSI TSL (Trusted List)](https://ec.europa.eu/digital-building-blocks/sites/default/files/TSL_specification_v2.3.4.pdf)
