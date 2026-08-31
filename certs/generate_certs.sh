#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1

CERTS_DIR="certs"
CA_DIR="$CERTS_DIR/ca"
GW_DIR="$CERTS_DIR/gateway"
DEV_DIR="$CERTS_DIR/devices"
ATK_DIR="$CERTS_DIR/attacker"
DAYS=365

mkdir -p "$CA_DIR" "$GW_DIR" "$DEV_DIR" "$ATK_DIR"

echo "generating certs"
echo ""

echo "[1/6] testbed CA"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$CA_DIR/testbed-ca.key" \
  -out "$CA_DIR/testbed-ca.crt" \
  -days $DAYS \
  -subj "/C=IE/ST=Dublin/O=UCD BCI Testbed/CN=Testbed CA"

echo "[2/6] gateway server cert"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$GW_DIR/gateway.key" \
  -out "$GW_DIR/gateway.csr" \
  -subj "/C=IE/ST=Dublin/O=UCD BCI Testbed/CN=localhost"

printf "[v3_req]\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = localhost\nIP.1 = 127.0.0.1\n" > "$GW_DIR/gateway_ext.cnf"

openssl x509 -req \
  -in "$GW_DIR/gateway.csr" \
  -CA "$CA_DIR/testbed-ca.crt" \
  -CAkey "$CA_DIR/testbed-ca.key" \
  -CAcreateserial \
  -out "$GW_DIR/gateway.crt" \
  -days $DAYS \
  -extfile "$GW_DIR/gateway_ext.cnf" \
  -extensions v3_req

rm -f "$GW_DIR/gateway.csr" "$GW_DIR/gateway_ext.cnf"

for DEVICE_NUM in 001 002; do
  DEVICE_ID="bci-device-${DEVICE_NUM}"
  echo "[3/6] device cert: $DEVICE_ID"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$DEV_DIR/device-${DEVICE_NUM}.key" \
    -out "$DEV_DIR/device-${DEVICE_NUM}.csr" \
    -subj "/C=IE/ST=Dublin/O=UCD BCI Testbed/CN=${DEVICE_ID}"

  openssl x509 -req \
    -in "$DEV_DIR/device-${DEVICE_NUM}.csr" \
    -CA "$CA_DIR/testbed-ca.crt" \
    -CAkey "$CA_DIR/testbed-ca.key" \
    -CAcreateserial \
    -out "$DEV_DIR/device-${DEVICE_NUM}.crt" \
    -days $DAYS

  rm -f "$DEV_DIR/device-${DEVICE_NUM}.csr"
done

echo "[4/6] attacker CA"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$ATK_DIR/attacker-ca.key" \
  -out "$ATK_DIR/attacker-ca.crt" \
  -days $DAYS \
  -subj "/C=IE/ST=Dublin/O=Attacker Corp/CN=Attacker CA"

echo "[5/6] attacker device cert"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$ATK_DIR/attacker.key" \
  -out "$ATK_DIR/attacker.csr" \
  -subj "/C=IE/ST=Dublin/O=Attacker Corp/CN=bci-device-001"

openssl x509 -req \
  -in "$ATK_DIR/attacker.csr" \
  -CA "$ATK_DIR/attacker-ca.crt" \
  -CAkey "$ATK_DIR/attacker-ca.key" \
  -CAcreateserial \
  -out "$ATK_DIR/attacker.crt" \
  -days $DAYS

rm -f "$ATK_DIR/attacker.csr"

echo "[6/6] variant device certs (negative-test fixtures)"

# expired but otherwise valid device cert: chains to the testbed CA, CN matches
# the allowlist, but notAfter is in the past. openssl x509 cannot backdate, so
# the cert is issued via openssl ca with explicit start/end dates (ATK1
# expired-cert test).
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DEV_DIR/device-expired.key" \
  -out "$DEV_DIR/device-expired.csr" \
  -subj "/C=IE/ST=Dublin/O=UCD BCI Testbed/CN=bci-device-001"

printf '[ca]\ndefault_ca = CA_default\n[CA_default]\ndatabase = %s/index.txt\nnew_certs_dir = %s\ncertificate = %s/testbed-ca.crt\nprivate_key = %s/testbed-ca.key\nserial = %s/serial\ndefault_md = sha256\npolicy = policy_anything\ncopy_extensions = none\n[policy_anything]\ncommonName = supplied\ncountryName = optional\nstateOrProvinceName = optional\norganizationName = optional\n' \
  "$CA_DIR" "$CA_DIR" "$CA_DIR" "$CA_DIR" "$CA_DIR" > "$CA_DIR/expired.cnf"
: > "$CA_DIR/index.txt"
echo "01" > "$CA_DIR/serial"

openssl ca -batch -config "$CA_DIR/expired.cnf" \
  -in "$DEV_DIR/device-expired.csr" \
  -out "$DEV_DIR/device-expired.crt" \
  -startdate 230101000000Z -enddate 230102000000Z

rm -f "$DEV_DIR/device-expired.csr" \
  "$CA_DIR/index.txt" "$CA_DIR/index.txt.attr" "$CA_DIR/index.txt.old" \
  "$CA_DIR/serial" "$CA_DIR/serial.old" "$CA_DIR/expired.cnf" "$CA_DIR/01.pem"

# valid CA-signed cert whose CN differs from the allowlist only by letter case
# (ATK4 case-mismatch test)
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DEV_DIR/device-upper.key" \
  -out "$DEV_DIR/device-upper.csr" \
  -subj "/C=IE/ST=Dublin/O=UCD BCI Testbed/CN=BCI-DEVICE-001"
openssl x509 -req \
  -in "$DEV_DIR/device-upper.csr" \
  -CA "$CA_DIR/testbed-ca.crt" \
  -CAkey "$CA_DIR/testbed-ca.key" \
  -CAcreateserial \
  -out "$DEV_DIR/device-upper.crt" \
  -days $DAYS
rm -f "$DEV_DIR/device-upper.csr"

# valid CA-signed cert whose CN contains an allowlisted id as a substring
# (ATK4 substring test)
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DEV_DIR/device-substr.key" \
  -out "$DEV_DIR/device-substr.csr" \
  -subj "/C=IE/ST=Dublin/O=UCD BCI Testbed/CN=bci-device-001-rogue"
openssl x509 -req \
  -in "$DEV_DIR/device-substr.csr" \
  -CA "$CA_DIR/testbed-ca.crt" \
  -CAkey "$CA_DIR/testbed-ca.key" \
  -CAcreateserial \
  -out "$DEV_DIR/device-substr.crt" \
  -days $DAYS
rm -f "$DEV_DIR/device-substr.csr"

echo ""
echo "done"
echo ""
echo "verify device cert:  openssl verify -CAfile $CA_DIR/testbed-ca.crt $DEV_DIR/device-001.crt"
echo "verify attacker cert SHOULD FAIL: openssl verify -CAfile $CA_DIR/testbed-ca.crt $ATK_DIR/attacker.crt"
