#!/usr/bin/env python3
"""Reject release packages containing node identity or live configuration."""

import io
import json
import pathlib
import subprocess
import sys
import tarfile


def check_config(data, name):
    config = json.loads(data)
    assert config.get("license_tier") == "community", name
    assert not config.get("admin_token"), name
    assert not config.get("mesh_secret"), name
    assert not config.get("trusted_network_sharing_enabled"), name
    assert not config.get("trusted_mesh_network_enabled"), name
    marketplace = config.get("marketplace", {})
    assert not marketplace.get("refresh_url"), name
    assert not marketplace.get("node_token"), name
    exchange = config.get("exchange", {})
    for field in ("enabled", "node_id", "tenant_id", "shared_secret"):
        assert not exchange.get(field), (name, field)
    security = config.get("security", {})
    for field in ("ca_cert", "cert_file", "key_file"):
        assert security.get(field, "").startswith("certs/"), (name, field)


def inspect_tar(path):
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        member = next(item for item in archive.getmembers() if item.name.endswith("/honeymesh.json"))
        assert member.mode == 0o600, path
        config = archive.extractfile(member).read()
    return names, config


def inspect_deb(path):
    data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(path)])
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        names = archive.getnames()
        member = next(item for item in archive.getmembers() if item.name.endswith("/honeymesh.json"))
        assert member.mode == 0o600, path
        config = archive.extractfile(member).read()
    return names, config


def inspect_rpm(path):
    names = subprocess.check_output(["rpm", "-qpl", str(path)], text=True).splitlines()
    unpack = subprocess.Popen(["rpm2cpio", str(path)], stdout=subprocess.PIPE)
    try:
        config = subprocess.check_output(
            ["cpio", "-i", "--to-stdout", "./etc/honeymesh/honeymesh.json"],
            stdin=unpack.stdout,
            stderr=subprocess.DEVNULL,
        )
    finally:
        unpack.stdout.close()
        assert unpack.wait() == 0, path
    return names, config


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--amd64-only"):
        raise SystemExit("usage: verify-release-packs.py DIST_DIR [--amd64-only]")
    folder = pathlib.Path(sys.argv[1])
    paths = sorted(folder.rglob("*.deb")) + sorted(folder.rglob("*.rpm")) + sorted(folder.rglob("*.tar.gz"))
    expected = 3 if len(sys.argv) == 3 else 6
    assert len(paths) == expected, f"expected {expected} packages, found {len(paths)}"
    for path in paths:
        inspect = inspect_deb if path.suffix == ".deb" else inspect_rpm if path.suffix == ".rpm" else inspect_tar
        names, config = inspect(path)
        for name in names:
            assert not name.endswith((".key", "license.json", "cluster.id", "honeymesh.db")), (path, name)
        assert any(name.endswith("init-local-certs.sh") for name in names), path
        check_config(config, path.name)
        print("PASS", path.name)


if __name__ == "__main__":
    main()
