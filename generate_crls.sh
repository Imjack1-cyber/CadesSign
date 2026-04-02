#!/bin/bash

# CRL Generation Script
# Generates Certificate Revocation Lists for Root and Intermediate CAs

set -e

echo "Generating CRLs..."

# ============================================================================
# Root CA CRL
# ============================================================================

# Create Root CA database directory and files
mkdir -p .ca/root
touch .ca/root/index.txt
echo "01" > .ca/root/serial

# Create Root CA config file
cat > .ca/root/ca.cnf <<'EOF'
[ca]
default_ca = CA_default

[CA_default]
database = .ca/root/index.txt
serial = .ca/root/serial
new_certs_dir = .ca/root/certs
default_md = sha256

[crl_ext]
authorityKeyIdentifier = keyid:always,issuer
EOF

# Generate Root CA CRL
openssl ca -gencrl \
    -config .ca/root/ca.cnf \
    -keyfile keys/root.key \
    -cert certs/root.crt \
    -out crls/root.crl \
    -crldays 365 \
    -notext \
    2>/dev/null || true

# Convert to DER
if [ -f crls/root.crl ]; then
    openssl crl -in crls/root.crl -outform DER -out crls/root.crl.der
    echo "✓ Root CA CRL: crls/root.crl (PEM) and crls/root.crl.der (DER)"
fi

# ============================================================================
# Intermediate CA CRL
# ============================================================================

# Create Intermediate CA database directory and files
mkdir -p .ca/intermediate
touch .ca/intermediate/index.txt
echo "01" > .ca/intermediate/serial

# Create Intermediate CA config file
cat > .ca/intermediate/ca.cnf <<'EOF'
[ca]
default_ca = CA_default

[CA_default]
database = .ca/intermediate/index.txt
serial = .ca/intermediate/serial
new_certs_dir = .ca/intermediate/certs
default_md = sha256

[crl_ext]
authorityKeyIdentifier = keyid:always,issuer
EOF

# Generate Intermediate CA CRL
openssl ca -gencrl \
    -config .ca/intermediate/ca.cnf \
    -keyfile keys/intermediate.key \
    -cert certs/intermediate.crt \
    -out crls/intermediate.crl \
    -crldays 365 \
    -notext \
    2>/dev/null || true

# Convert to DER
if [ -f crls/intermediate.crl ]; then
    openssl crl -in crls/intermediate.crl -outform DER -out crls/intermediate.crl.der
    echo "✓ Intermediate CA CRL: crls/intermediate.crl (PEM) and crls/intermediate.crl.der (DER)"
fi

rm -rf .ca/

echo ""
echo "CRL generation complete!"
