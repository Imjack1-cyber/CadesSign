# Security

## Reporting a vulnerability

Report vulnerabilities privately to the maintainers, for example as a
confidential issue in the project's tracker, not a public one. Include the
`cades --version` output and steps to reproduce.

## What `cades` protects, and what it does not

- **Test-grade material is labelled.** The test PKI, the in-process TSA and
  revocation data minted from a CA key in a key file make signatures that
  prove nothing to third parties. Every use prints `TEST-ONLY:` on stderr;
  `sign --strict` refuses them.
- **Secrets stay off the command line** when passed as `env:VAR`, `file:PATH`
  or through the prompt. Literal values work but print a warning.
- **Verification is offline.** `verify` uses only the trust anchors given to
  it and the material embedded in the signature; it never fetches anything.
  `--trust-lotl` reads a local cache.
- **Trusted lists must be validly signed and current.** Lists whose signature
  does not verify against the LOTL signing certificates, or that have expired,
  contribute no trust anchors.
- **Endpoints are not restricted.** `sign` contacts whatever TSA, OCSP and CRL
  URLs it is given or finds in the certificates. Whoever runs it controls
  these inputs; do not pass untrusted URLs.
- **Private keys in files** are only as safe as the file and its password.
  For qualified signatures the key must be on a QSCD and used through PKCS#11.

## Dependencies

CI checks dependencies against the NVD (`vulnerability-check`, failing on
CVSS 7 or higher once an NVD API key is configured), runs GitLab SAST and
secret detection, and runs SpotBugs with FindSecBugs in every `mvn verify`.
Each release ships a CycloneDX SBOM.

The web app in `webapp/` is a demo without authentication. Do not expose it
on a network.
