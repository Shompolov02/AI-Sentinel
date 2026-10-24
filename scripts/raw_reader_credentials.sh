#!/bin/sh
# Add separate reader credentials under the existing laboratory CA.
set -eu
umask 077
cert_dir=${1:?Usage: sh scripts/raw_reader_credentials.sh secrets/core}
test -f "$cert_dir/ca.crt"
test -f "$cert_dir/ca.key"
for name in raw-reader.key raw-reader.crt raw-reader-tokens raw-reader.csr raw-reader.ext; do
    if [ -e "$cert_dir/$name" ]; then
        echo 'Refusing to overwrite reader material; use a fresh staging directory.' >&2
        exit 1
    fi
done
chmod 700 "$cert_dir"
openssl req -newkey rsa:3072 -nodes -sha256 -subj '/CN=raw-reader' \
    -keyout "$cert_dir/raw-reader.key" -out "$cert_dir/raw-reader.csr" 2>/dev/null
cat > "$cert_dir/raw-reader.ext" <<'EXT'
subjectAltName=DNS:raw-reader
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -sha256 -days 90 -in "$cert_dir/raw-reader.csr" \
    -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
    -extfile "$cert_dir/raw-reader.ext" -out "$cert_dir/raw-reader.crt" 2>/dev/null
openssl rand -hex 32 > "$cert_dir/raw-reader-tokens"
chmod 644 "$cert_dir/raw-reader.key" "$cert_dir/raw-reader.crt" "$cert_dir/raw-reader-tokens"
rm "$cert_dir/raw-reader.csr" "$cert_dir/raw-reader.ext"
echo 'Reader TLS certificate and separate service token created; validity 90 days.'
