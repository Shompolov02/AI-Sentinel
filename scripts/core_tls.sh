#!/bin/sh
# Issue a laboratory CA and a DNS-verified intake certificate. No keys are printed.
set -eu
umask 077
cert_dir=${1:?Usage: sh scripts/core_tls.sh secrets/core}
mkdir -p "$cert_dir"
chmod 700 "$cert_dir"
if [ -e "$cert_dir/intake.key" ] || [ -e "$cert_dir/ca.key" ] || [ -e "$cert_dir/intake.crt" ]; then
    echo 'Refusing to overwrite TLS material; use a fresh staging directory.' >&2
    exit 1
fi
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
    -subj '/CN=AI-Sentinel laboratory Core CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt" 2>/dev/null
openssl req -newkey rsa:3072 -nodes -sha256 \
    -subj '/CN=core-intake' \
    -keyout "$cert_dir/intake.key" -out "$cert_dir/intake.csr" 2>/dev/null
cat > "$cert_dir/intake.ext" <<'EXT'
subjectAltName=DNS:core-intake
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -sha256 -days 90 -in "$cert_dir/intake.csr" \
    -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
    -extfile "$cert_dir/intake.ext" -out "$cert_dir/intake.crt" 2>/dev/null
chmod 644 "$cert_dir/intake.key" "$cert_dir/intake.crt" "$cert_dir/ca.crt"
# Only individual server files are mounted. CA key stays 0600 under host 0700 dir.
rm "$cert_dir/intake.csr" "$cert_dir/intake.ext"
echo 'TLS material created; CA validity 365 days, intake certificate validity 90 days.'
