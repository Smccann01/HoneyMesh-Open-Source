#!/usr/bin/env python3
"""Verify an Admin-signed Node release manifest against the exact two artifacts."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


PINNED_PUBLISHER = "D67F75E94480FC5F974885F30DC7BAB5FD2544D1"
GUARD_NAME = "honeymesh-node-guard-0.1.2.tgz"
PRO_NAME = "honeymesh_2.3.6-rc4-nodepro2_amd64.deb"
GUARD_SOURCE = "d6cbae83aab25fc173323e3007908111aa05cdf2"
PRO_SOURCE = "de590b1185f8325396b3613c8a9328eaa83f5038"


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verified_signer(manifest: Path, signature: Path, public_key: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="hm-node-publisher-") as home:
        os.chmod(home, 0o700)
        base = ["gpg", "--batch", "--homedir", home]
        subprocess.run(base + ["--import", str(public_key)], check=True, capture_output=True)
        keys = subprocess.run(base + ["--with-colons", "--fingerprint", "--list-keys"],
                              check=True, capture_output=True, text=True)
        fingerprints = {line.split(":")[9] for line in keys.stdout.splitlines() if line.startswith("fpr:")}
        if len(fingerprints) != 1:
            raise ValueError("Expected exactly one publisher public key")
        signer = next(iter(fingerprints))
        signed = subprocess.run(base + ["--status-fd", "1", "--verify", str(signature), str(manifest)],
                                check=True, capture_output=True, text=True)
        valid = {line.split()[2] for line in signed.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")}
        if valid != {signer}:
            raise ValueError("Manifest signature does not match the publisher public key")
        return signer


def verify_release(manifest: Path, signature: Path, public_key: Path, guard: Path, node_pro: Path,
                   expected_fingerprint: str = PINNED_PUBLISHER) -> dict:
    if not re.fullmatch(r"[A-F0-9]{40}", expected_fingerprint):
        raise ValueError("Invalid expected publisher fingerprint")
    if verified_signer(manifest, signature, public_key) != expected_fingerprint:
        raise ValueError("Publisher fingerprint does not match the pinned key")
    record = json.loads(manifest.read_text())
    if (record.get("schema_version") != 1 or record.get("product") != "HoneyMesh-Node-private-candidate" or
            record.get("publisher_fingerprint") != expected_fingerprint or
            record.get("qualification_state") != "private_candidate"):
        raise ValueError("Unexpected Node release manifest identity")
    entries = record.get("artifacts")
    if not isinstance(entries, list) or len(entries) != 2:
        raise ValueError("Expected exactly two Node artifacts")
    by_product = {entry.get("product"): entry for entry in entries if isinstance(entry, dict)}
    if set(by_product) != {"node_guard", "node_pro"}:
        raise ValueError("Unexpected Node artifact products")
    for product, file, name, version, platform, source in (
        ("node_guard", guard, GUARD_NAME, "0.1.2", "Node.js 20 or newer", GUARD_SOURCE),
        ("node_pro", node_pro, PRO_NAME, "2.3.6-rc4-nodepro2", "Ubuntu 24.04 AMD64", PRO_SOURCE),
    ):
        entry = by_product[product]
        if (file.name != name or entry.get("path") != name or entry.get("version") != version or
                entry.get("platform") != platform or type(entry.get("bytes")) is not int or
                entry["bytes"] != file.stat().st_size or digest(file) != entry.get("sha256") or
                entry.get("source_commit") != source):
            raise ValueError(f"Signed manifest does not match the {product} artifact")
    with tarfile.open(guard, "r:gz") as archive:
        package = json.load(archive.extractfile("package/package.json"))
    if package.get("name") != "@honeymesh/node-guard" or package.get("version") != "0.1.2":
        raise ValueError("Guard archive package identity mismatch")
    version = subprocess.check_output(["dpkg-deb", "-f", str(node_pro), "Version"], text=True).strip()
    arch = subprocess.check_output(["dpkg-deb", "-f", str(node_pro), "Architecture"], text=True).strip()
    if version != "2.3.6-rc4-nodepro2" or arch != "amd64":
        raise ValueError("Node Pro Debian identity mismatch")
    with tempfile.TemporaryDirectory(prefix="hm-node-binary-") as unpacked:
        subprocess.run(["dpkg-deb", "-x", str(node_pro), unpacked], check=True, capture_output=True)
        binary = Path(unpacked) / "usr/bin/honeymesh"
        build = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
    if (f"vcs.revision={by_product['node_pro']['source_commit']}" not in build or
            "vcs.modified=false" not in build):
        raise ValueError("Node Pro binary source revision mismatch")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--guard", required=True, type=Path)
    parser.add_argument("--node-pro", required=True, type=Path)
    args = parser.parse_args()
    verify_release(args.manifest, args.signature, args.public_key, args.guard, args.node_pro)
    print("Signed Node Guard and Node Pro artifacts verified")


if __name__ == "__main__":
    main()
