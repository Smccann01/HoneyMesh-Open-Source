#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo 'HoneyMesh service setup requires root' >&2
  exit 1
fi

if ! getent group honeymesh >/dev/null; then
  groupadd --system honeymesh
fi
if ! getent passwd honeymesh >/dev/null; then
  useradd --system --gid honeymesh --home-dir /var/lib/honeymesh --shell /usr/sbin/nologin honeymesh
fi

config_dir=/etc/honeymesh
config_file=$config_dir/honeymesh.json
cert_dir=$config_dir/certs
state_dir=/var/lib/honeymesh

for path in "$config_dir" "$config_file" "$cert_dir" "$cert_dir/ca" "$cert_dir/node" "$cert_dir/ca/ca.key" "$state_dir"; do
  if [ -L "$path" ]; then
    echo "HoneyMesh setup refuses symlink: $path" >&2
    exit 1
  fi
done
if [ ! -f "$config_file" ]; then
  echo "HoneyMesh config missing: $config_file" >&2
  exit 1
fi
if [ ! -f "$cert_dir/ca/ca.key" ]; then
  echo "HoneyMesh CA key missing: $cert_dir/ca/ca.key" >&2
  exit 1
fi
if [ ! -d "$state_dir" ]; then
  mkdir -p "$state_dir"
fi
if [ -n "$(find "$state_dir" -xdev -type l -print -quit)" ]; then
  echo 'HoneyMesh setup refuses symlinks in the state directory' >&2
  exit 1
fi
if [ -n "$(find "$state_dir" -xdev -type f -links +1 -print -quit)" ]; then
  echo 'HoneyMesh setup refuses hard-linked state files' >&2
  exit 1
fi

marker=$state_dir/.service-user-migrated-236
if [ ! -e "$marker" ]; then
  install -d -m 0700 -o root -g root /var/backups/honeymesh
  backup=$(mktemp -d /var/backups/honeymesh/pre-236.XXXXXX)
  chmod 0700 "$backup"
  cp -a "$config_file" "$backup/honeymesh.json"
  cp -a "$state_dir" "$backup/state"
  echo "HoneyMesh state backup: $backup"
fi

chown root:honeymesh "$config_dir" "$config_file" "$cert_dir" "$cert_dir/ca" "$cert_dir/node"
chmod 0750 "$config_dir" "$cert_dir" "$cert_dir/ca" "$cert_dir/node"
chmod 0640 "$config_file"
for path in "$cert_dir/ca/ca.crt" "$cert_dir/node/node.crt" "$cert_dir/node/node.key"; do
  if [ -L "$path" ] || [ ! -f "$path" ]; then
    echo "HoneyMesh certificate is missing or a symlink: $path" >&2
    exit 1
  fi
  chown root:honeymesh "$path"
  chmod 0640 "$path"
done
chown root:root "$cert_dir/ca/ca.key"
chmod 0600 "$cert_dir/ca/ca.key"

chown -R honeymesh:honeymesh "$state_dir"
find "$state_dir" -xdev -type d -exec chmod 0700 {} +
find "$state_dir" -xdev -type f -exec chmod 0600 {} +
if [ ! -e "$marker" ]; then
  install -m 0600 -o honeymesh -g honeymesh /dev/null "$marker"
fi
