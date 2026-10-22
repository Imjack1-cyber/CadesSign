# Running `cades` in production

This guide is for whoever runs `cades` in production: setting it up on a
server or workstation, wiring it into scripts, and keeping it healthy. For
what the tool does and how to build it, see the [README](../README.md).

## Checklist

- [ ] Java 21 on the machine; `cades --version` shows the expected version.
- [ ] Every production `sign` call uses `--strict`.
- [ ] Passwords and PINs come from `env:VAR` or `file:PATH`, never literally.
- [ ] The signing key is on a PKCS#11 token or HSM (required for QES), or in a
      PKCS#12 file readable only by the signing account.
- [ ] `--tsa-url` points at a qualified timestamp authority, if signatures
      must be qualified.
- [ ] The machine can reach the TSA and the CA's OCSP/CRL URLs (in the signer
      certificate's AIA and CRL distribution point extensions).
- [ ] If you use `verify --trust-lotl`: a daily `cades tl refresh` job, and
      monitoring on its exit code.
- [ ] Scripts check exit codes (table below), not output text.

## Exit codes

| Code | `sign` | `verify` | `tl refresh` / `tl status` |
|---|---|---|---|
| 0 | reaches the requested level | passed (TOTAL_PASSED) | LOTL and at least one national list valid |
| 1 | written, but below the requested level; deleted with `--strict` | failed or indeterminate | — |
| 2 | invalid options or arguments, missing input file | same | invalid options |
| 3 | keys, token, files or a network service could not be used | files or keys could not be read; trusted list cache missing or stale | LOTL not downloadable or not validly signed; cache missing or stale |

Errors go to stderr as one line starting with `Error:`. Add `-v` for DSS's
progress log and a stack trace.

## Strict mode

`--strict` turns every test-only shortcut into an error:

| Refused | Because |
|---|---|
| `--generate-keystore` | a fresh test PKI proves nothing to anyone else |
| levels above B without `--tsa-url` | the in-process TSA is not a trusted timestamp authority |
| OCSP/CRL data minted with a CA key from the key file | only the CA's real services may vouch for revocation status |
| `--keystore` without `--keystore-password` | the built-in default password is the test PKI's |

It also implies `--online-revocation`, and deletes the signature when the
self-check finds that it falls short of the requested level.

Without `--strict`, each of these shortcuts prints a `TEST-ONLY:` line on
stderr. Alert on that string if you collect logs.

## Secrets

Every password and PIN option accepts:

| Form | Example | Notes |
|---|---|---|
| `env:VAR` | `--pin env:CARD_PIN` | recommended for services and CI |
| `file:PATH` | `--keystore-password file:/run/secrets/ks` | first line, without the line ending |
| no value | `--pin` | prompts on the console; fails without one |
| literal | `--pin 1234` | works, with a warning: visible in `ps` and shell history |

## Signing keys on a smartcard or HSM (PKCS#11)

`cades` talks to tokens through the vendor's PKCS#11 library. Typical
libraries:

| Device | Library |
|---|---|
| SoftHSM2 (testing) | `/usr/lib/softhsm/libsofthsm2.so` |
| OpenSC-supported cards, incl. many signature cards | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| YubiKey (PIV) | `libykcs11.so` from yubico-piv-tool |
| Network HSMs (Thales Luna, Utimaco, Entrust nShield, …) | the vendor's client library |

Find the slot with OpenSC's `pkcs11-tool --module <lib> --list-slots`, then
list the keys and pick one:

```bash
cades pkcs11 list --pkcs11-lib <lib> --pkcs11-slot <id> --pin env:PIN
cades sign doc.pdf --strict --pkcs11-lib <lib> --pkcs11-slot <id> \
    --pkcs11-key <alias> --pin env:PIN --tsa-url https://tsa.example/tsr
```

- Without `--pkcs11-slot`, the first slot with a token is used;
  `--pkcs11-slot-index <n>` selects by position instead.
- `--pkcs11-key` can be left out when the token holds exactly one key.
- When the token holds only the signer certificate, give the CA certificates
  with `--signer-chain ca.pem`. With `--online-revocation` (implied by
  `--strict`), missing CA certificates are also fetched from the AIA URLs.
- The PIN is requested only if the token asks for one, so PIN-pad readers
  work without `--pin`.

`cades pkcs11 list` and `sign` print `Qualified certificate: yes, key on a
QSCD: yes/no` when the certificate has QC statements. `--strict` warns when
a qualified certificate does not declare a QSCD.

### Trying it out with SoftHSM2

```bash
export SOFTHSM2_CONF=$HOME/softhsm2.conf
mkdir -p $HOME/softhsm-tokens
echo "directories.tokendir = $HOME/softhsm-tokens" > $SOFTHSM2_CONF
softhsm2-util --init-token --free --label test --so-pin 12345678 --pin 1234
# Import a key and certificate, e.g. with pkcs11-tool --write-object, or see
# src/test/java/com/example/cades/Pkcs11IT.java for a Java-only way.
```

## EU trusted lists (`verify --trust-lotl`)

`verify --trust-lotl` trusts the trust services on the EU List of Trusted
Lists (LOTL) and the national lists it points to. DSS then also determines
whether a signature is **QESig** (qualified), **AdESig-QC** or **AdESig**,
shown as `Qualification` in the summary and as `qualification` in
`--report json`. Without `--keystore`, the trusted lists are the only trust
anchors.

### The LOTL signing certificates

A downloaded LOTL is trusted only if a certificate announced by the European
Commission in the Official Journal of the EU signed it. `cades` does not ship
these certificates. Provide them with `--lotl-keystore`, as PEM or PKCS#12:

1. Take the certificates from the current Official Journal announcement. The
   default `--lotl-oj-url` points at it, and the LOTL itself references it.
2. Check their fingerprints against the announcement, then save them as one
   PEM file, e.g. `/etc/cades/lotl-signers.pem`.
3. When the Commission announces new certificates, the LOTL's pivot mechanism
   carries the trust forward, so the file rarely needs updating.

### Keeping the cache fresh

`verify --trust-lotl` reads only the local cache and never downloads. Refresh
the cache daily:

```cron
# m h dom mon dow  command
15 3 * * *  cades tl refresh --lotl-keystore /etc/cades/lotl-signers.pem --tl-cache /var/cache/cades/tl || logger -t cades "trusted list refresh failed"
```

- `cades tl status` prints the cached lists offline, and exits 3 when the
  cache is older than `--tl-max-age` days (default 14).
- `verify` refuses a cache older than `--tl-max-age` the same way. Use
  `--tl-max-age 0` only for archived validations where an old state is
  intended.
- A list whose signature does not verify, or that has expired, contributes no
  trust anchors; `tl refresh` marks it `NOT USED`.
- The default cache is `~/.cache/cades/tl` (or `$XDG_CACHE_HOME/cades/tl`).
  Share one cache between users with `--tl-cache`.

## Network access

`sign` contacts:

- the TSA (`--tsa-url`)
- the OCSP responders and CRL distribution points named in the certificates
  (`--online-revocation`, `--strict`), or the ones given with
  `--ocsp-url`/`--crl-url`
- AIA URLs for missing CA certificates

`verify` never goes online. `tl refresh` downloads the LOTL and the national
lists.

## Logging

- stdout carries only results (summary, JSON, XML report), so it can be
  parsed.
- stderr carries `Error:`, `Warning:` and `TEST-ONLY:` lines and DSS's log at
  WARN level.
- `-v` raises the log to INFO and prints stack traces; `-q` lowers it to
  ERROR.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `sign` cannot reach LT: no revocation data, or exit 1 below the requested level | add `--online-revocation`, or check that the OCSP/CRL URLs of both the signer and the TSA chain are reachable |
| `Error: ... revoked` | the signer or TSA certificate is revoked; get a new certificate |
| `Error: ... expired` | the signer certificate has expired |
| `the token holds N keys; choose one with --pkcs11-key` | several keys on the token; use an alias from `cades pkcs11 list` |
| PKCS#11 login fails, exit 3 | wrong PIN, or the token is locked after too many attempts |
| `verify --trust-lotl` exits 3: cache empty or too old | run `cades tl refresh`; check its cron job |
| `tl refresh`: `the LOTL is not valid` | `--lotl-keystore` lacks the current signing certificate, or the download was blocked |
| Qualification `AdESig-QC` instead of `QESig` | the certificate does not declare a QSCD, or the trusted list does not list the key as on a QSCD |
