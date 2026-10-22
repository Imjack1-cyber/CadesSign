# CAdES B-LT Signer & Verifier

Creates and checks electronic signatures in the **CAdES Baseline** format
(ETSI EN 319 122-1), up to level **B-LT**: signatures that can still be
validated years later, after the certificates involved have expired. It comes
as a command-line tool and as a web app, and works fully offline out of the
box.

> By default, keys and timestamps come from a disposable test PKI, so those
> signatures prove nothing to third parties, and the tool says so on every
> run (`TEST-ONLY`). With a certificate from a real CA, a real timestamp
> authority and the CA's own OCSP/CRL services, it makes genuine CAdES B-LT
> signatures; `--strict` guarantees that nothing test-grade slips in. With a
> qualified certificate on a signature card or HSM (PKCS#11), the signatures
> are qualified (QES), and `verify --trust-lotl` confirms that against the EU
> trusted lists.

## What it can do

- **Sign** any file (XML, text, binaries) as a detached `.p7s` or with the
  content enveloped inside the signature
- **Choose the level**: B, B-T, LT (default) or LTA
- **Verify** a signature and report the level it actually reaches, as a
  short summary, JSON for scripts, or a full DSS XML report; the exit code
  says whether it passed
- **Bring your own keys**: PKCS#12/PFX or PEM files, a smartcard or HSM
  through PKCS#11 (`--pkcs11-lib`), or a fresh test PKI with one flag
- **Go online when needed**: use a real RFC 3161 timestamp server
  (`--tsa-url`) and the CA's OCSP/CRL services, from the certificates
  themselves (`--online-revocation`) or given explicitly (`--ocsp-url`,
  `--crl-url`)
- **Check qualification** against the EU List of Trusted Lists
  (`verify --trust-lotl`, cache kept by `cades tl refresh`)
- **Keep secrets off the command line**: passwords and PINs as `env:VAR`,
  `file:PATH` or a prompt
- **Run a timestamp server** for testing (`cades tsa`)
- **Web app**: a step-by-step wizard for signing and verifying, a readable
  validation report, and a dashboard of past operations

## How it works

Signing builds on the European Commission's [DSS](https://github.com/esig/dss)
library, with BouncyCastle for keys and certificates:

1. **B-B**: DSS creates a CMS signature over the file's exact bytes.
2. **B-T**: a timestamp authority adds an RFC 3161 timestamp that proves when
   the signature existed. By default this TSA runs inside the process.
3. **B-LT**: the certificate chain and revocation data (CRL/OCSP) are
   embedded in the signature, so validating it later needs nothing from
   outside. Offline, the tool creates this revocation data itself, dated
   after the timestamp as the standard requires.
4. **B-LTA** (optional): an archive timestamp is added over everything above.

The verifier gets only the trust anchor and no network access. A signature
only passes as LT if everything it needs really is embedded.

The web app is a React front end (Siemens iX) talking to a small Express
backend, which runs the CLI's fat jar for each request and logs operations in
SQLite.

| Path | Contents |
|---|---|
| `src/main/java/com/example/cades/` | CLI and signing/verification logic |
| `webapp/backend/` | Express API (`/api/sign`, `/api/verify`, `/api/stats`) |
| `webapp/frontend/` | React + Vite web app |
| `webapp/database/` | SQLite schema |

## Getting started

Requirements: **Java 21**, **Maven**, and for the web app **Node.js 20+**.

### Command line

```bash
mvn package -DskipTests   # builds target/cades-lt.jar
make install         # optional: installs `cades` to ~/.local/bin (must be on your PATH)

cades sign hello.txt --generate-keystore test-pki.p12   # first run: create test keys -> hello.txt.p7s
cades sign hello.txt --keystore test-pki.p12            # later runs reuse them
cades verify hello.txt hello.txt.p7s --keystore test-pki.p12
cades verify hello.txt hello.txt.p7s --keystore test-pki.p12 --report full
cades --help                                            # all commands and options
```

Keystore passwords default to the test PKI's. For anything else, pass them
without exposing them in the process list: `--keystore-password env:VAR`,
`--keystore-password file:/run/secrets/pw`, or `--keystore-password` alone to
be prompted.

Without `make install`, run the jar directly:
`java -jar target/cades-lt.jar sign ...`

### Web app

Build the jar first (`mvn package`), then start the backend and the front end
in two terminals:

```bash
cd webapp/backend && npm install && npm start      # API on http://localhost:3001
cd webapp/frontend && npm install && npm run dev   # app on http://localhost:5173
```

Open http://localhost:5173. The dev server forwards `/api` to the backend.
The backend can be configured with `PORT`, `JAR_PATH` and `DB_PATH`.

### Tests

```bash
mvn verify                             # unit + integration tests, coverage gate, SpotBugs
mvn verify -Dcades.slowTests=true      # also signs a 1 GB file within a 256 MB heap
src/test/scripts/cli-smoke.sh          # the packaged jar end to end, incl. OpenSSL interop
cd webapp/frontend && npm test         # front end unit tests
```

The integration tests run real HTTP services (TSA, OCSP, CRL, trusted lists)
on the loopback interface. The PKCS#11 tests need SoftHSM2
(`apt install softhsm2`) and are skipped without it.

## Going to production

Sign with `--strict`. It refuses the in-process TSA, revocation data minted
from a CA key, generated keystores and the default password, fetches OCSP/CRL
data from the CA's own services, and deletes the signature if it does not
reach the requested level:

```bash
cades sign contract.pdf --strict \
    --pkcs11-lib /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --pin env:CARD_PIN \
    --tsa-url https://qualified-tsa.example/tsr
cades verify contract.pdf contract.pdf.p7s --trust-lotl --lotl-keystore lotl-signers.pem
```

| Exit code | `sign` | `verify` |
|---|---|---|
| 0 | the signature reaches the requested level | the signature passed |
| 1 | written, but below the requested level (deleted with `--strict`) | failed or indeterminate |
| 2 | invalid options or arguments | invalid options or arguments |
| 3 | keys, token, files or a network service could not be used | files or keys could not be read |

The tool alone does not make a signature qualified. That takes a qualified
certificate whose key lives on a certified QSCD, and a qualified timestamp
authority. Whether this software needs certification as a signature creation
application for your use case is a compliance question.

[docs/operations.md](docs/operations.md) covers PKCS#11 setup, the trusted
list cache, logging and troubleshooting.
