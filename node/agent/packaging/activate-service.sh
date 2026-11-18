#!/bin/sh
set -eu

if [ ! -d /run/systemd/system ]; then
  echo 'HoneyMesh installed; systemd is not running, so start it with the service user on this host.'
  exit 0
fi
systemctl daemon-reload
if systemctl is-active --quiet honeymesh.service; then
  systemctl try-restart honeymesh.service
elif pgrep -x honeymesh >/dev/null 2>&1; then
  echo 'HoneyMesh manual process detected; stop it before enabling honeymesh.service.'
else
  systemctl enable --now honeymesh.service
fi
