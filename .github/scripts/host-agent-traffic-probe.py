#!/usr/bin/env python3
"""Exercise one XDP ban on the isolated CI veth pair; print no credentials."""

import json
import pathlib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


snap_name = sys.argv[1]
state = pathlib.Path("/var/snap") / snap_name / "common/runtime-state.json"
token = json.loads(state.read_text())["admin_token"]
assert token
base = "https://127.0.0.1:8443"
tls = ssl._create_unverified_context()  # Per-host pilot certificate on loopback only.


def request(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"X-Honey-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=tls, timeout=3) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def ping():
    result = subprocess.run(
        ["ping", "-I", "hm-strict-peer", "-c", "1", "-W", "1", "198.18.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


for _ in range(20):
    try:
        status, mode = request("GET", "/api/mode")
        if status == 200:
            break
    except (OSError, TimeoutError):
        pass
    time.sleep(0.5)
else:
    raise RuntimeError("local HoneyMesh dashboard did not become ready")

assert mode["mode"] == "TEST", mode
assert ping() or ping(), "baseline veth traffic failed before enforcement"
status, _ = request("POST", "/api/ban", {"ip": "198.18.0.2", "ttl_seconds": 30})
assert status == 409, f"TEST accepted manual ban: {status}"

status, mode = request("POST", "/api/mode", {"mode": "ENFORCE"})
assert status == 200 and mode["mode"] == "ENFORCE", (status, mode)
try:
    status, before = request("GET", "/api/xdp/drop-totals")
    assert status == 200, (status, before)
    status, result = request(
        "POST", "/api/ban", {"ip": "198.18.0.2", "reason": "isolated-ci-probe", "ttl_seconds": 30}
    )
    assert status == 200, (status, result)
    assert not ping(), "isolated source was not blocked by XDP"
    status, after = request("GET", "/api/xdp/drop-totals")
    assert status == 200 and after["ipv4"]["packets"] > before["ipv4"]["packets"], (status, before, after)
    status, result = request("POST", "/api/ban/release", {"ip": "198.18.0.2"})
    assert status == 200, (status, result)
    assert ping() or ping(), "traffic did not recover after release"
    print("TRAFFIC_PROBE=blocked_counted_released")
finally:
    status, mode = request("POST", "/api/mode", {"mode": "TEST"})
    assert status == 200 and mode["mode"] == "TEST", (status, mode)
