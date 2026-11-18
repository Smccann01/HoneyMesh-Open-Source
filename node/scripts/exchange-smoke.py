#!/usr/bin/env python3
"""Authenticate to the local agent socket without exposing the bridge secret."""

import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import sys
from datetime import datetime, timezone


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=3)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(self.path)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: exchange-smoke.py SOCKET SECRET_FILE")
    socket_path, secret_path = sys.argv[1:]
    if not os.path.isabs(socket_path):
        raise SystemExit("socket path must be absolute")
    with open(secret_path, "rb") as stream:
        secret = stream.read().strip()
    if len(secret) < 32:
        raise SystemExit("bridge secret is too short")
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    nonce = secrets.token_hex(16)
    signature = hmac.new(secret, f"{timestamp}\n{nonce}\n".encode(), hashlib.sha256).hexdigest()
    connection = UnixHTTPConnection(socket_path)
    connection.request("GET", "/v1/active-blocks", headers={
        "X-Edge-Timestamp": timestamp,
        "X-Edge-Nonce": nonce,
        "X-Edge-Signature": signature,
    })
    response = connection.getresponse()
    body = response.read(32768)
    if response.status != 200:
        raise SystemExit(f"agent socket returned HTTP {response.status}")
    data = json.loads(body)
    if data.get("mode") != "TEST" or data.get("total") != 0:
        raise SystemExit("agent is not in TEST mode with zero app blocks")
    print("agent socket authenticated: TEST, zero app blocks")


if __name__ == "__main__":
    main()
