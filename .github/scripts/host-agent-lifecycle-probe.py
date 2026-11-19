#!/usr/bin/env python3
"""Check a CI-only host agent's private state and TEST mode without printing secrets."""

import hashlib
import json
import pathlib
import ssl
import sys
import urllib.request


phase, snap_name = sys.argv[1:]
assert phase in ("before", "after", "state")
root = pathlib.Path("/var/snap") / snap_name / "common"
config_file = root / "honeymesh.json"
key_file = root / "certs/node/node.key"
state_file = root / "runtime-state.json"
config = json.loads(config_file.read_text())
state = json.loads(state_file.read_text())
assert config["interfaces"] == ["hm-strict-test"]
assert config["trusted_network_sharing_enabled"] is False
assert config["trusted_mesh_network_enabled"] is False
assert key_file.is_file()
token = state["admin_token"]
assert token

fingerprints = {
    "config": hashlib.sha256(config_file.read_bytes()).hexdigest(),
    "key": hashlib.sha256(key_file.read_bytes()).hexdigest(),
    "token": hashlib.sha256(token.encode()).hexdigest(),
}
record_file = pathlib.Path("/tmp") / f"{snap_name}-lifecycle-fingerprints.json"
if phase == "before":
    record_file.write_text(json.dumps(fingerprints))
else:
    assert fingerprints == json.loads(record_file.read_text()), "private state changed across crash/restart"
if phase == "after":
    request = urllib.request.Request(
        "https://127.0.0.1:8443/api/mode", headers={"X-Honey-Token": token}
    )
    with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=5) as response:
        assert response.status == 200
        mode = json.load(response)
    assert mode["mode"] == "TEST", mode

print(f"LIFECYCLE_PROBE={phase}_private_state_ok")
