# CAdES B-LT Demo

Signs XML files with **CAdES Baseline LT** (ETSI EN 319 122-1) using the
European Commission's [DSS](https://github.com/esig/dss) library, with a
disposable test PKI and an in-process RFC 3161 timestamp authority.

Runs entirely offline. No network, no ports, no external services.

---

## Which "CAdES-LT"?

There are two things called CAdES-LT, and they are not the same:

| | |
|---|---|
| **CAdES B-LT** — ETSI EN 319 122-1 | The baseline *level*: B-B + signature timestamp + embedded validation material. **This is what this project implements.** |
| **CAdES-LT** — ETSI TS 101 733 §6.5 | The `long-term-validation` attribute. [TS 101 733][ts101733] defines this, **and deprecates it**: *"The use of the CAdES-LT form is deprecated for any signature to which a long-term-validation attribute has not already been applied."* |

TS 101 733 V2.2.1 is referenced for background only. It is not redistributed
here — download it free of charge from ETSI:

[ts101733]: https://www.etsi.org/deliver/etsi_TS/101700_101799/101733/02.02.01_60/ts_101733v020201p.pdf

```bash
mkdir -p spec && curl -Lo spec/ts_101733v020201p.pdf \
    https://www.etsi.org/deliver/etsi_TS/101700_101799/101733/02.02.01_60/ts_101733v020201p.pdf
```

## What B-LT actually requires

LT is not "a signature plus a timestamp". It is a signature that can still be
validated years from now, after certificates have expired:

1. **B-B** — CMS SignedData with `signing-certificate-v2`, `content-type`,
   `message-digest`, `mime-type` and CMS algorithm protection.
2. **B-T** — an RFC 3161 timestamp over the signature value, proving *when* it
   existed.
3. **B-LT** — the certificate chain **and revocation data** embedded inside
   the signature, so validation needs nothing external.

Step 3 is where implementations quietly go wrong. DSS does not silently emit a
weaker signature when revocation data is unavailable — with the default
`ExceptionOnStatusAlert` it aborts with
`"Revocation data is missing for one or more certificate(s)."`

A subtler trap: revocation data must be dated **strictly after the signature
timestamp**, because that is what proves the certificate was still live at
signing. Material generated before signing is always too old, and DSS reports
`"No revocation data found after the best signature time"`. See
`OfflineRevocation.revocationTime()`.

## Quick start — install and run

```bash
mvn package
make install
# ensure ~/.local/bin is in your PATH
cades --help
cades sign hello.txt --generate-keystore test-pki.p12   # first run: create keys, -> hello.txt.p7s
cades sign hello.txt --keystore test-pki.p12            # later runs reuse them
cades verify hello.txt hello.txt.p7s --keystore test-pki.p12
cades verify hello.txt.p7s --keystore test-pki.p12 --report full
cades sign --packaging enveloping hello.txt -o signed.p7s --keystore test-pki.p12
cades verify signed.p7s --keystore test-pki.p12         # no original needed
cades tsa --port 9999 --count 5
```

`make install` copies the fat jar to `~/.local/share/cades/` and the
wrapper scripts to `~/.local/bin/`. Add `~/.local/bin` to your PATH
(if not already) and `cades` is available everywhere.

### Without `make install`

```bash
mvn package
java -jar target/cades-lt-demo-1.0.0-SNAPSHOT-fat.jar sign hello.txt --generate-keystore test-pki.p12
```

The `-fat.jar` is a single self-contained executable -- no `lib/`
directory needed.

## Running it (Maven)

```bash
mvn test                 # 7 tests: LT level, tamper detection, RFC 3161 compliance
```

The CLI is built on picocli and has four subcommands:

```bash
mvn compile exec:java -Dexec.args="gen-pki"                          # (re-)generate the test PKI
mvn compile exec:java -Dexec.args="sign hello.txt --keystore test-pki.p12"  # sign, write hello.txt.p7s
mvn compile exec:java -Dexec.args="verify hello.txt hello.txt.p7s"   # verify, compact summary
mvn compile exec:java -Dexec.args="verify hello.txt hello.txt.p7s --report full"  # XML report
mvn compile exec:java -Dexec.args="tsa --port 9999 --count 5"        # one-shot RFC 3161 HTTP TSA
```

`sign` refuses to run without keys. Choose exactly one source:

| Option | Effect |
|---|---|
| `--keystore PATH` / `--keystore-password PW` | existing PKCS#12 with `root`, `signer` and `tsa` entries (password default `passwort`). A missing file is an error, never created implicitly |
| `--generate-keystore PATH` | create a new test PKI in `PATH` (protected by `--keystore-password`), then sign with it. Never overwrites |
| `--signer FILE` / `--signer-password PW` | signer key + certificate chain from its own PKCS#12/PFX or PEM file |

`--tsa FILE` / `--tsa-password PW` loads the in-process TSA's key and
chain from a separate PKCS#12/PFX or PEM file. It overrides the
keystore's `tsa` entry, and `--signer` needs it for levels above B
unless `--tsa-url` is given. File formats are detected from the
content, so PEM may hold certificates and (optionally encrypted)
PKCS#1/PKCS#8 keys in any order.

Offline LT mints CRL/OCSP responses with the issuing CA's key, so a
`--signer`/`--tsa` file must also contain the CA's private key. Without
it, signing stops with a hint to add `--ocsp-url`/`--crl-url` or use
`--level B-T`.

Further options:

| Option | Effect |
|---|---|
| *(defaults)* | in-process TSA + offline revocation (fully offline) |
| `--tsa-url URL` | online RFC 3161 TSA, e.g. the `tsa` subcommand or a real TSA |
| `--ocsp-url URL` / `--crl-url URL` | online revocation endpoints instead of the offline ones; repeatable |
| `--digest SHA512` | digest algorithm (default SHA256) |
| `--level B\|B-T\|LT\|LTA` | target level (default LT) |
| `--packaging detached\|enveloping` | detached (default) or content inside the signature |

Every subcommand accepts `--keystore` and `--keystore-password`.

**LT constraint with an online TSA.** An external TSA (e.g.
FreeTSA) chains to a CA the offline revocation sources know
nothing about, so `--tsa-url` plus offline revocation can only
reach **B-T** — the CLI prints a warning to that effect. Full
LT with an online TSA requires `--ocsp-url`/`--crl-url`
endpoints that serve revocation data for *both* the signer
chain and the TSA chain. Pointing `--tsa-url` at the `tsa`
subcommand still reaches LT, because that server signs with
the demo PKI the offline sources do cover.

## Verifying with OpenSSL

The signatures are ordinary CMS and verify with standard tools — but
**`-binary` is mandatory**. Without it OpenSSL applies S/MIME text
canonicalisation (CRLF translation) before digesting, and verification fails
even though the signature is perfectly valid:

```bash
openssl cms -verify -binary -inform DER \
    -in invoice.xml.p7s \
    -content src/test/resources/samples/invoice.xml \
    -CAfile <your-ca>.pem -purpose any -out /dev/null
```

Inspect the CAdES structure:

```bash
openssl asn1parse -inform DER -in invoice.xml.p7s -i | grep OBJECT
```

## Why detached, and why CAdES over XML at all

CAdES signs opaque octets, so it neither knows nor cares that the payload is
XML. That is useful here: the bytes are signed exactly as they are, with no
canonicalisation step and therefore none of the XML-DSig canonicalisation
pitfalls. The cost is that the signature cannot live inside the XML — hence
**detached** packaging, which leaves the original file byte-identical and
writes the signature beside it as `.p7s`.

If you do not have an external requirement mandating CAdES, consider whether
**XAdES** (native XML signatures) or **ASiC-E** (a container holding both) fits
better. Switching this project to enveloping packaging is a `--packaging
enveloping` flag away.

## Structure

| File | Role |
|---|---|
| `TestPki` | Generates root CA, signing cert and TSA cert with BouncyCastle |
| `LocalTspSource` | Implements DSS's `TSPSource` as an in-process RFC 3161 TSA |
| `OfflineRevocation` | Mints CRLs and OCSP responses on demand, dated after the timestamp |
| `SigningConfig` | Selects TSA and revocation sources plus signing parameters |
| `CAdESLtSigner` | Wires DSS to produce a detached B-LT signature |
| `CAdESLtVerifier` | Validates and reports the level actually achieved |
| `Main` | picocli CLI root: `sign`, `verify`, `gen-pki`, `tsa` subcommands |
| `SignCommand` / `VerifyCommand` / `GenPkiCommand` / `TsaCommand` | The subcommands |
| `KeystoreOptions` | Shared `--keystore` / `--keystore-password` mixin |

`CAdESLtVerifier` is deliberately starved: it is given the trust anchor and
nothing else — no CRL source, no OCSP source, no network AIA fetcher. Any
revocation data it uses must therefore have come from *inside* the signature.
That turns "is this really LT?" from a claim into a test.

## Going to production

This demo is **not** legally valid. The trust anchor is a disposable CA
stored in `test-pki.p12` (overridable via `--keystore` /
`--keystore-password`), and the timestamps assert nothing more than
the local system clock. Three changes make it real:

1. **Signing key** — replace `TestPki` with a PKCS#12 keystore or a PKCS#11
   token (add `dss-token` and use `Pkcs12SignatureToken` /
   `Pkcs11SignatureToken`). Only `CAdESLtSigner.computeSignature` touches the
   private key.
2. **Timestamps** — pass `--tsa-url` pointing at a real TSA
   (DSS's `OnlineTSPSource`). Nothing else changes; `TSPSource`
   is the seam. Remember the LT constraint above: supply real
   `--ocsp-url`/`--crl-url` endpoints for the TSA's chain too.
3. **Trust and revocation** — replace `OfflineRevocation` with DSS's online
   CRL/OCSP sources, restore the default AIA source, and load a real trust
   list (e.g. the EU LOTL via `dss-tsl-validation`).

### Known limitations

- **RSA 2048 / SHA-256.** Satisfies the DSS default cryptographic constraints.
  Raise the key size in `TestPki.KEY_SIZE` if your validation policy is
  stricter.
- **Not LTA.** At LT there is no archive timestamp, so DSS logs
  `"Revocation data is missing for one or more POE(s)"` for the TSA
  certificate. This is inherent to the LT level, not a defect — switching
  `SignatureLevel` to `CAdES_BASELINE_LTA` makes the warning disappear. LTA is
  what you want for genuinely long-term archival.
- **One signer, flat hierarchy.** A single self-signed root issues both the
  signing and TSA certificates, so one CRL covers everything. Real hierarchies
  have intermediates and need revocation data for each.
