#!/usr/bin/env python3
"""Qualify a published HoneyMesh DEB on a disposable Linux VM.

The active probe uses only a private veth and network namespace. It refuses to
run on a host with an existing HoneyMesh installation or without the explicit
disposable-host marker created by the workflow.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


HOST_IF = "hmq-host"
PEER_IF = "hmq-peer"
NETNS = "hmq-client"
HOST_IP = "198.18.0.1"
BLOCKED_IP = "198.18.0.2"
CONTROL_IP = "198.18.0.3"
MARKER = Path("/run/honeymesh-qualification-disposable")
CONFIG = Path("/etc/honeymesh/honeymesh.json")
STATE = Path("/var/lib/honeymesh/runtime-state.json")
NODE_KEY = Path("/etc/honeymesh/certs/node/node.key")
BASE = "https://127.0.0.1:8443"


class ProbeError(RuntimeError):
    pass


def run(*argv: str, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode:
        # Command arguments and logs can include local credentials. Report only
        # the executable and exit status; detailed logs stay on the disposable VM.
        raise ProbeError(f"{argv[0]} exited {result.returncode}")
    return result


def host_facts() -> dict:
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    mount = run("findmnt", "-n", "-o", "TARGET", "-t", "bpf", check=False)
    return {
        "distribution": os_release.get("ID", "unknown"),
        "distribution_version": os_release.get("VERSION_ID", "unknown"),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "bpffs_mounted": mount.returncode == 0 and "/sys/fs/bpf" in mount.stdout.splitlines(),
        "kernel_btf_present": Path("/sys/kernel/btf/vmlinux").is_file(),
    }


def api(token: str, method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"X-Honey-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    # This endpoint is fixed to loopback and uses a certificate created on this VM.
    tls = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=tls, timeout=4) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def ready_token() -> str:
    for _ in range(40):
        if STATE.is_file():
            token = json.loads(STATE.read_text()).get("admin_token", "")
            if token:
                try:
                    status, mode = api(token, "GET", "/api/mode")
                    if status == 200 and isinstance(mode, dict):
                        return token
                except (OSError, ValueError):
                    pass
        time.sleep(0.5)
    raise ProbeError("local dashboard did not become ready")


def ping(source: str) -> bool:
    result = run(
        "ip", "netns", "exec", NETNS, "ping", "-n", "-I", source,
        "-c", "1", "-W", "1", HOST_IP, timeout=5, check=False,
    )
    return result.returncode == 0


def wait_ping(source: str, expected: bool) -> bool:
    for _ in range(4):
        if ping(source) == expected:
            return True
        time.sleep(0.5)
    return False


def xdp_state() -> tuple[bool, bool]:
    result = run("ip", "-details", "link", "show", HOST_IF, check=False)
    attached = result.returncode == 0 and "prog/xdp" in result.stdout
    return attached, attached and "xdpgeneric" in result.stdout


def create_isolated_network() -> None:
    run("ip", "netns", "add", NETNS)
    run("ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF)
    run("ip", "link", "set", PEER_IF, "netns", NETNS)
    run("ip", "address", "add", HOST_IP + "/29", "dev", HOST_IF)
    run("ip", "link", "set", HOST_IF, "up")
    run("ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up")
    run("ip", "netns", "exec", NETNS, "ip", "address", "add", BLOCKED_IP + "/29", "dev", PEER_IF)
    run("ip", "netns", "exec", NETNS, "ip", "address", "add", CONTROL_IP + "/29", "dev", PEER_IF)
    run("ip", "netns", "exec", NETNS, "ip", "link", "set", PEER_IF, "up")


def require(status: bool, message: str) -> None:
    if not status:
        raise ProbeError(message)


def qualify(package: Path, report_path: Path, release_tag: str) -> int:
    report = {
        "schema_version": 1,
        "release_tag": release_tag,
        "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        "host": host_facts(),
        "checks": {},
        "result": "failed",
        "limitations": [
            "Disposable VM only; no production qualification.",
            "Generic XDP on an isolated veth; native NIC and throughput were not tested.",
            "One exact source was blocked; a control source remained reachable.",
        ],
    }
    checks = report["checks"]
    original_config = None
    token = ""
    installed = False
    network_may_exist = False
    try:
        require(os.geteuid() == 0, "active qualification requires root")
        require(MARKER.is_file(), "disposable-host marker is missing")
        require(not CONFIG.exists() and not STATE.exists(), "existing HoneyMesh state is present")
        require(run("dpkg-query", "-W", "honeymesh", check=False).returncode != 0,
                "HoneyMesh is already installed")
        require(report["host"]["bpffs_mounted"], "BPF filesystem is not mounted")
        require(NETNS not in run("ip", "netns", "list", check=False).stdout,
                "qualification namespace already exists")
        require(run("ip", "link", "show", HOST_IF, check=False).returncode != 0,
                "qualification interface already exists")

        run("dpkg", "-i", str(package), timeout=120)
        installed = True
        checks["package_installed"] = True
        version = run("dpkg-query", "-W", "-f=${Version}", "honeymesh").stdout.strip()
        report["installed_version"] = version
        require(run("systemctl", "is-active", "--quiet", "honeymesh.service", check=False).returncode == 0,
                "honeymesh service did not start")
        checks["service_started"] = True
        original_config = CONFIG.read_bytes()
        config = json.loads(original_config)
        require(config.get("interfaces") == [], "fresh install selected an interface")
        require(not config.get("trusted_network_sharing_enabled"), "fresh install enabled sharing")
        require(not config.get("trusted_mesh_network_enabled"), "fresh install enabled mesh")
        checks["safe_defaults"] = True
        token = ready_token()
        status, mode = api(token, "GET", "/api/mode")
        require(status == 200 and mode["mode"] == "TEST", "fresh install did not start in TEST")
        checks["test_mode"] = True
        private_key_before = hashlib.sha256(NODE_KEY.read_bytes()).digest()
        state_token_before = hashlib.sha256(token.encode()).digest()

        network_may_exist = True
        create_isolated_network()
        require(wait_ping(BLOCKED_IP, True) and wait_ping(CONTROL_IP, True),
                "isolated baseline traffic failed")
        checks["baseline_traffic"] = True
        config["interfaces"] = [HOST_IF]
        CONFIG.write_text(json.dumps(config) + "\n")
        run("systemctl", "restart", "honeymesh.service")
        token = ready_token()
        for _ in range(20):
            if xdp_state()[1]:
                break
            time.sleep(0.5)
        else:
            raise ProbeError("XDP did not attach to the isolated interface")
        checks["generic_xdp_attached"] = True
        status, _ = api(token, "POST", "/api/ban", {"ip": BLOCKED_IP, "ttl_seconds": 60})
        require(status == 409, "TEST accepted a manual block")
        checks["test_rejects_block"] = True
        status, mode = api(token, "POST", "/api/mode", {"mode": "ENFORCE"})
        require(status == 200 and mode["mode"] == "ENFORCE", "ENFORCE transition failed")
        status, before = api(token, "GET", "/api/xdp/drop-totals")
        require(status == 200, "drop counter was unavailable")
        status, _ = api(token, "POST", "/api/ban", {
            "ip": BLOCKED_IP, "reason": "isolated-release-qualification", "ttl_seconds": 60,
        })
        require(status == 200, "exact-source block was rejected")
        require(wait_ping(BLOCKED_IP, False), "selected source was not blocked")
        checks["selected_source_blocked"] = True
        require(wait_ping(CONTROL_IP, True), "unrelated control source lost reachability")
        checks["control_source_allowed"] = True
        status, after = api(token, "GET", "/api/xdp/drop-totals")
        require(status == 200 and after["ipv4"]["packets"] > before["ipv4"]["packets"],
                "XDP drop count did not increase")
        checks["drop_count_increased"] = True
        status, _ = api(token, "POST", "/api/ban/release", {"ip": BLOCKED_IP})
        require(status == 200 and wait_ping(BLOCKED_IP, True), "traffic did not recover after release")
        checks["release_restored_traffic"] = True
        status, mode = api(token, "POST", "/api/mode", {"mode": "TEST"})
        require(status == 200 and mode["mode"] == "TEST", "return to TEST failed")
        checks["returned_to_test"] = True
        CONFIG.write_bytes(original_config)
        original_config = None
        run("systemctl", "restart", "honeymesh.service")
        token = ready_token()
        require(not xdp_state()[0], "XDP remained attached after config restore")
        require(hashlib.sha256(NODE_KEY.read_bytes()).digest() == private_key_before,
                "node key changed after restart")
        require(hashlib.sha256(token.encode()).digest() == state_token_before,
                "admin token changed after restart")
        checks["state_preserved_and_xdp_detached"] = True
        report["result"] = "passed"
    except (ProbeError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        report["failure"] = str(exc)
    finally:
        cleanup_errors = []
        if installed and token:
            try:
                status, _ = api(token, "POST", "/api/mode", {"mode": "TEST"})
                if status != 200:
                    cleanup_errors.append("return to TEST failed during cleanup")
            except (OSError, ValueError):
                cleanup_errors.append("return to TEST unavailable during cleanup")
        try:
            if original_config is not None and CONFIG.exists():
                CONFIG.write_bytes(original_config)
                if run("systemctl", "restart", "honeymesh.service", check=False).returncode:
                    cleanup_errors.append("service restart failed during config restore")
            if network_may_exist:
                run("ip", "link", "delete", HOST_IF, check=False)
                run("ip", "netns", "delete", NETNS, check=False)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_errors.append("isolated network cleanup failed")
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            report["result"] = "failed"
            report.setdefault("failure", "; ".join(cleanup_errors))
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result": report["result"], "host": report["host"],
                          "checks": checks, "failure": report.get("failure")}, sort_keys=True))
    return 0 if report["result"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-only", action="store_true", help="read-only host facts")
    parser.add_argument("--package", type=Path, help="verified published AMD64 DEB")
    parser.add_argument("--report", type=Path, help="JSON report destination")
    parser.add_argument("--release-tag", help="published release tag")
    args = parser.parse_args()
    if args.inventory_only:
        print(json.dumps(host_facts(), sort_keys=True))
        return 0
    if not args.package or not args.report or not args.release_tag:
        parser.error("active qualification needs --package, --report, and --release-tag")
    return qualify(args.package.resolve(strict=True), args.report, args.release_tag)


if __name__ == "__main__":
    sys.exit(main())
