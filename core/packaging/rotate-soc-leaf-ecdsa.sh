#!/bin/sh
set -eu

# Rotate only the local node leaf. The existing CA stays in place so trusted
# mesh peers do not lose their trust anchor. Run as root in a maintenance window.
cert_dir=${HM_CERT_DIR:-/etc/honeymesh/certs}
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo sh packaging/rotate-soc-leaf-ecdsa.sh" >&2
  exit 1
fi
if [ "$cert_dir" != /etc/honeymesh/certs ] && [ "${HM_NO_RESTART:-0}" != 1 ]; then
  echo "A custom certificate directory requires HM_NO_RESTART=1." >&2
  exit 1
fi
ca_dir=$cert_dir/ca
node_dir=$cert_dir/node
for file in "$ca_dir/ca.crt" "$ca_dir/ca.key" "$node_dir/node.crt" "$node_dir/node.key"; do
  if [ ! -f "$file" ]; then echo "Missing $file" >&2; exit 1; fi
done

umask 077
work=$(mktemp -d "$cert_dir/.soc-leaf-rotation-XXXXXX")
cp -p "$node_dir/node.crt" "$work/previous.crt"
cp -p "$node_dir/node.key" "$work/previous.key"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -subj "/CN=honeymesh-node" -keyout "$work/next.key" -out "$work/next.csr" >/dev/null 2>&1
cat > "$work/next.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth
EOF
openssl x509 -req -in "$work/next.csr" -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" \
  -CAcreateserial -days 365 -extfile "$work/next.ext" -out "$work/next.crt" >/dev/null 2>&1
openssl verify -CAfile "$ca_dir/ca.crt" "$work/next.crt" >/dev/null
openssl x509 -in "$work/next.crt" -noout -pubkey > "$work/cert.pub"
openssl pkey -in "$work/next.key" -pubout > "$work/key.pub"
cmp "$work/cert.pub" "$work/key.pub" >/dev/null

install -m 0600 "$work/next.key" "$node_dir/node.key"
install -m 0644 "$work/next.crt" "$node_dir/node.crt"
chown --reference="$work/previous.key" "$node_dir/node.key"
chmod --reference="$work/previous.key" "$node_dir/node.key"
chown --reference="$work/previous.crt" "$node_dir/node.crt"
chmod --reference="$work/previous.crt" "$node_dir/node.crt"
if [ "${HM_NO_RESTART:-0}" != 1 ]; then
  ready=0
  expected_fingerprint=$(openssl x509 -in "$work/next.crt" -noout -fingerprint -sha256)
  if systemctl restart honeymesh; then
    attempt=0
    while [ "$attempt" -lt 10 ]; do
      actual_fingerprint=$(echo | timeout 3 openssl s_client -connect 127.0.0.1:8443 -servername localhost 2>/dev/null |
        openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)
      if systemctl is-active --quiet honeymesh && [ "$actual_fingerprint" = "$expected_fingerprint" ]; then
        ready=1
        break
      fi
      attempt=$((attempt + 1))
      sleep 1
    done
  fi
  if [ "$ready" != 1 ]; then
    install -m 0600 "$work/previous.key" "$node_dir/node.key"
    install -m 0644 "$work/previous.crt" "$node_dir/node.crt"
    chown --reference="$work/previous.key" "$node_dir/node.key"
    chmod --reference="$work/previous.key" "$node_dir/node.key"
    chown --reference="$work/previous.crt" "$node_dir/node.crt"
    chmod --reference="$work/previous.crt" "$node_dir/node.crt"
    systemctl restart honeymesh || true
    echo "HoneyMesh restart failed; previous leaf restored. Backup: $work" >&2
    exit 1
  fi
fi
echo "SOC leaf rotated. Update the firewall console certificate pin before resuming host controls."
openssl x509 -in "$node_dir/node.crt" -noout -fingerprint -sha256
echo "Previous leaf backup: $work"
