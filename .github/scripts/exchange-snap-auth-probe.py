#!/usr/bin/env python3
"""Exercise installed Exchange admin auth without printing generated credentials."""

import base64
import hashlib
import hmac
import json
import pathlib
import struct
import time
import urllib.error
import urllib.request

credentials = pathlib.Path("/var/snap/network-decode-exchange/common/private/admin-credentials.txt")
values = dict(line.split(": ", 1) for line in credentials.read_text().splitlines() if ": " in line)
key = base64.b32decode(values["Authenticator setup key"])
counter = struct.pack(">Q", int(time.time() // 30))
digest = hmac.new(key, counter, hashlib.sha1).digest()
offset = digest[-1] & 15
code = str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)
base = "http://127.0.0.1:8790"
headers = {"Host": "exchange.example.test", "Origin": "https://exchange.example.test",
           "X-Forwarded-Proto": "https", "Content-Type": "application/json"}


def request(path, body=None, cookie=None):
    current = dict(headers)
    if cookie:
        current["Cookie"] = cookie
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers=current, method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.status, json.load(response), response.headers


status, payload, response_headers = request("/api/admin/session", {
    "email": values["Email"], "password": values["Password"], "code": code,
})
assert status == 200 and payload["admin"]["email"] == values["Email"]
cookie = response_headers["Set-Cookie"].split(";", 1)[0]
status, payload, _ = request("/api/admin/status", cookie=cookie)
assert status == 200 and payload["clusterId"] == "example-cluster" and payload["sharingEnabled"] is False
status, payload, _ = request("/api/admin/enrollment-token", {}, cookie=cookie)
assert status == 201 and len(payload["token"]) > 30
print("EXCHANGE_SNAP_PROBE=admin_login_status_and_enrollment_token_passed")
