#!/bin/bash

# Update unified_trustlist.xml with generated certificates and CRL distribution points

set -e

cd "$(dirname "$0")"/..  # Navigate to project root from scripts folder

echo "Updating unified_trustlist.xml..."

# Configuration
CERT_DIR="certs"
CRL_DIR="crls"
TSL_FILE="tsl/unified_trustlist.xml"
TSL_BACKUP="$TSL_FILE.backup"

mkdir -p tsl/

# Check if certificates exist
if [ ! -f "$CERT_DIR/root.crt" ] || [ ! -f "$CERT_DIR/intermediate.crt" ]; then
    echo "Error: Certificates not found. Run ./generate_cert_chain.sh first."
    exit 1
fi

# Backup original file if it exists
if [ -f "$TSL_FILE" ]; then
    cp "$TSL_FILE" "$TSL_BACKUP"
    echo "✓ Backed up original file to ${TSL_BACKUP}"
else
    echo "✓ Creating new trustlist (original not found)"
fi

# Extract certificates in base64 format
ROOT_CERT=$(openssl x509 -in "$CERT_DIR/root.crt" -outform PEM | sed -n '/-----BEGIN/,/-----END/p' | grep -v -e "-----BEGIN" -e "-----END" | tr -d '\n')
INTERMEDIATE_CERT=$(openssl x509 -in "$CERT_DIR/intermediate.crt" -outform PEM | sed -n '/-----BEGIN/,/-----END/p' | grep -v -e "-----BEGIN" -e "-----END" | tr -d '\n')

# Format CRL distribution point paths
CRL_ROOT_PATH="file://$(pwd)/${CRL_DIR}/root.crl.der"
CRL_INTERMEDIATE_PATH="file://$(pwd)/${CRL_DIR}/intermediate.crl.der"

# Create a new TSL with updated certificates
cat > "$TSL_FILE" <<'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<ns:TrustServiceStatusList xmlns:ns="http://uri.etsi.org/02231/v2#"
  TSLTag="http://uri.etsi.org/TL/TSLTag/201612">
  <ns:SchemeInformation>
    <ns:TSLVersionIdentifier>5</ns:TSLVersionIdentifier>
    <ns:TSLSequenceNumber>1</ns:TSLSequenceNumber>
    <ns:TSLType>EUgeneric</ns:TSLType>
    <ns:SchemeOperatorName>
      <ns:Name xml:lang="en">CadesSign Test Authority</ns:Name>
    </ns:SchemeOperatorName>
    <ns:SchemeOperatorAddress>
      <ns:PostalAddresses>
        <ns:PostalAddress xml:lang="en">
          <ns:StreetAddress>Test Address 1</ns:StreetAddress>
          <ns:Locality>Berlin</ns:Locality>
          <ns:PostalCode>10115</ns:PostalCode>
          <ns:CountryName>Germany</ns:CountryName>
        </ns:PostalAddress>
      </ns:PostalAddresses>
      <ns:ElectronicAddress>
        <ns:URI xml:lang="en">https://example.com</ns:URI>
      </ns:ElectronicAddress>
    </ns:SchemeOperatorAddress>
    <ns:SchemeName>
      <ns:Name xml:lang="en">CadesSign Test Scheme</ns:Name>
    </ns:SchemeName>
    <ns:SchemeInformationURI>
      <ns:URI xml:lang="en">https://example.com/tsl</ns:URI>
    </ns:SchemeInformationURI>
    <ns:StatusDeterminationApproach>http://uri.etsi.org/TL/StatusDeterm/appropriate</ns:StatusDeterminationApproach>
    <ns:SchemeTerritory>DE</ns:SchemeTerritory>
    <ns:PolicyOrLegalNotice>
      <ns:TSLLegalNotice xml:lang="en">Test TSL for CadesSign validation</ns:TSLLegalNotice>
    </ns:PolicyOrLegalNotice>
    <ns:HistoricalInformationPeriod>2592000</ns:HistoricalInformationPeriod>
    <ns:ListIssueDateTime>2026-04-02T00:00:00Z</ns:ListIssueDateTime>
    <ns:NextUpdate>
      <ns:dateTime>2027-04-02T00:00:00Z</ns:dateTime>
    </ns:NextUpdate>
  </ns:SchemeInformation>
  <ns:TrustServiceProviderList>
    <ns:TrustServiceProvider>
      <ns:TSPInformation>
        <ns:TSPName>
          <ns:Name xml:lang="en">CadesSign Trust Service</ns:Name>
        </ns:TSPName>
        <ns:TSPAddress>
          <ns:PostalAddresses>
            <ns:PostalAddress xml:lang="en">
              <ns:StreetAddress>Test Address 1</ns:StreetAddress>
              <ns:Locality>Berlin</ns:Locality>
              <ns:PostalCode>10115</ns:PostalCode>
              <ns:CountryName>Germany</ns:CountryName>
            </ns:PostalAddress>
          </ns:PostalAddresses>
          <ns:ElectronicAddress>
            <ns:URI xml:lang="en">https://example.com</ns:URI>
          </ns:ElectronicAddress>
        </ns:TSPAddress>
        <ns:TSPInformationURI>
          <ns:URI xml:lang="en">https://example.com</ns:URI>
        </ns:TSPInformationURI>
      </ns:TSPInformation>
      <ns:TSPServices>
        <ns:TSPService>
          <ns:ServiceInformation>
            <ns:ServiceTypeIdentifier>http://uri.etsi.org/TL0142/svctype/CA/PKC</ns:ServiceTypeIdentifier>
            <ns:ServiceName>
              <ns:Name xml:lang="en">Root CA Certificate</ns:Name>
            </ns:ServiceName>
            <ns:ServiceDigitalIdentity>
              <ns:DigitalId>
                <ns:X509Certificate>
                  ROOTCERTPLACEHOLDER
                </ns:X509Certificate>
              </ns:DigitalId>
            </ns:ServiceDigitalIdentity>
            <ns:ServiceStatus>granted</ns:ServiceStatus>
            <ns:StatusStartingTime>2026-04-02T00:00:00Z</ns:StatusStartingTime>
            <ns:ServiceInformationExtensions>
              <ns:Extension Critical="false">
                <ns:ExternalServiceInformation>
                  <ns:CRLDistributionPoints>
                    <ns:URI xml:lang="en">ROOTCRLPLACEHOLDER</ns:URI>
                  </ns:CRLDistributionPoints>
                </ns:ExternalServiceInformation>
              </ns:Extension>
            </ns:ServiceInformationExtensions>
          </ns:ServiceInformation>
        </ns:TSPService>
        <ns:TSPService>
          <ns:ServiceInformation>
            <ns:ServiceTypeIdentifier>http://uri.etsi.org/TL0142/svctype/CA/PKC</ns:ServiceTypeIdentifier>
            <ns:ServiceName>
              <ns:Name xml:lang="en">Intermediate CA Certificate</ns:Name>
            </ns:ServiceName>
            <ns:ServiceDigitalIdentity>
              <ns:DigitalId>
                <ns:X509Certificate>
                  INTERMEDIATECERTPLACEHOLDER
                </ns:X509Certificate>
              </ns:DigitalId>
            </ns:ServiceDigitalIdentity>
            <ns:ServiceStatus>granted</ns:ServiceStatus>
            <ns:StatusStartingTime>2026-04-02T00:00:00Z</ns:StatusStartingTime>
            <ns:ServiceInformationExtensions>
              <ns:Extension Critical="false">
                <ns:ExternalServiceInformation>
                  <ns:CRLDistributionPoints>
                    <ns:URI xml:lang="en">INTERMEDIATECRLPLACEHOLDER</ns:URI>
                  </ns:CRLDistributionPoints>
                </ns:ExternalServiceInformation>
              </ns:Extension>
            </ns:ServiceInformationExtensions>
          </ns:ServiceInformation>
        </ns:TSPService>
      </ns:TSPServices>
    </ns:TrustServiceProvider>
  </ns:TrustServiceProviderList>
</ns:TrustServiceStatusList>
XMLEOF

# Replace placeholders with actual certificate data and CRL paths
sed -i "s|ROOTCERTPLACEHOLDER|${ROOT_CERT}|g" "$TSL_FILE"
sed -i "s|INTERMEDIATECERTPLACEHOLDER|${INTERMEDIATE_CERT}|g" "$TSL_FILE"
sed -i "s|ROOTCRLPLACEHOLDER|${CRL_ROOT_PATH}|g" "$TSL_FILE"
sed -i "s|INTERMEDIATECRLPLACEHOLDER|${CRL_INTERMEDIATE_PATH}|g" "$TSL_FILE"

echo "✓ Updated Root CA certificate"
echo "✓ Updated Intermediate CA certificate"
echo "✓ Updated Root CA CRL distribution point: ${CRL_ROOT_PATH}"
echo "✓ Updated Intermediate CA CRL distribution point: ${CRL_INTERMEDIATE_PATH}"
echo ""
echo "Updated unified_trustlist.xml successfully!"
