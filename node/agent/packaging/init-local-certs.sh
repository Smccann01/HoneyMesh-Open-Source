#!/bin/sh
set -eu

cert_dir=${1:-/etc/honeymesh/certs}
ca_dir=$cert_dir/ca
node_dir=$cert_dir/node

if [ -f "$ca_dir/ca.crt" ] && [ -f "$ca_dir/ca.key" ] && [ -f "$node_dir/node.crt" ] && [ -f "$node_dir/node.key" ]; then
  exit 0
fi
if [ -e "$ca_dir/ca.crt" ] || [ -e "$ca_dir/ca.key" ] || [ -e "$node_dir/node.crt" ] || [ -e "$node_dir/node.key" ]; then
  echo "HoneyMesh certificate setup is incomplete; inspect $cert_dir before retrying." >&2
  exit 1
fi

umask 077
mkdir -p "$ca_dir" "$node_dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 3650 \
  -subj "/CN=HoneyMesh local CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$ca_dir/ca.key" -out "$ca_dir/ca.crt" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj "/CN=honeymesh-node" \
  -keyout "$node_dir/node.key" -out "$node_dir/node.csr" >/dev/null 2>&1
ext_file=$(mktemp)
trap 'rm -f "$ext_file" "$node_dir/node.csr"' EXIT HUP INT TERM
cat > "$ext_file" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth
EOF
openssl x509 -req -in "$node_dir/node.csr" \
  -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" -CAcreateserial \
  -days 365 -extfile "$ext_file" -out "$node_dir/node.crt" >/dev/null 2>&1
chmod 0600 "$ca_dir/ca.key" "$node_dir/node.key"
echo "Generated unique local HoneyMesh certificates in $cert_dir."
