#!/usr/bin/env sh
# End-to-end check of the packaged CLI: signs every sample with a fresh
# test PKI, verifies each signature, and asserts exit codes and levels.
# Usage: src/test/scripts/cli-smoke.sh [path/to/cades-lt.jar] [output dir]
set -eu

JAR="${1:-target/cades-lt.jar}"
OUT="${2:-out}"
SAMPLES="src/test/resources/samples"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

cades() {
    java -jar "$JAR" "$@"
}

[ -f "$JAR" ] || fail "jar not found: $JAR (run mvn package first)"
rm -rf "$OUT"
mkdir -p "$OUT"

export CADES_SMOKE_PASSWORD="smoke-$$"
KEYSTORE="$OUT/test-pki.p12"

cades --version

for sample in "$SAMPLES"/*; do
    name=$(basename "$sample")
    case "$name" in *.p7s) continue ;; esac  # leftovers of local runs
    signature="$OUT/$name.p7s"
    if [ -f "$KEYSTORE" ]; then
        keys="--keystore $KEYSTORE"
    else
        keys="--generate-keystore $KEYSTORE"
    fi

    # shellcheck disable=SC2086 # $keys is two words on purpose
    cades sign "$sample" -o "$signature" $keys \
        --keystore-password env:CADES_SMOKE_PASSWORD > "$OUT/$name.sign.txt" \
        || fail "signing $name exited $?"
    grep -q "Level reached      : CAdES-BASELINE-LT" "$OUT/$name.sign.txt" \
        || fail "$name was not signed at LT"
    test -s "$signature" || fail "$signature is empty"

    cades verify "$sample" "$signature" --keystore "$KEYSTORE" \
        --keystore-password env:CADES_SMOKE_PASSWORD --report json > "$OUT/$name.verify.json" \
        || fail "verifying $name exited $?"
    grep -q '"indication":"TOTAL_PASSED"' "$OUT/$name.verify.json" \
        || fail "$name did not pass verification"

    # Interoperability: OpenSSL must accept the CMS signature over the
    # original bytes. -binary is mandatory: without it OpenSSL applies
    # S/MIME canonicalisation and the content digest no longer matches.
    if command -v openssl > /dev/null; then
        [ -f "$OUT/certs.pem" ] || openssl pkcs12 -in "$KEYSTORE" -nokeys \
            -passin env:CADES_SMOKE_PASSWORD -out "$OUT/certs.pem" 2> /dev/null \
            || fail "openssl cannot read $KEYSTORE"
        openssl cms -verify -binary -inform DER -in "$signature" -content "$sample" \
            -CAfile "$OUT/certs.pem" -purpose any -out /dev/null 2> "$OUT/$name.openssl.txt" \
            || fail "openssl cms -verify rejects $signature: $(cat "$OUT/$name.openssl.txt")"
    fi
    echo "ok: $name"
done

# A changed document must fail with exit code 1, not crash.
first=$(ls "$SAMPLES" | grep -v '\.p7s$' | head -n 1)
cp "$SAMPLES/$first" "$OUT/tampered"
echo "tampered" >> "$OUT/tampered"
set +e
cades verify "$OUT/tampered" "$OUT/$first.p7s" --keystore "$KEYSTORE" \
    --keystore-password env:CADES_SMOKE_PASSWORD > /dev/null 2>&1
code=$?
set -e
[ "$code" -eq 1 ] || fail "tampered document: expected exit code 1, got $code"
echo "ok: tampered document rejected"

echo "All CLI smoke checks passed."
