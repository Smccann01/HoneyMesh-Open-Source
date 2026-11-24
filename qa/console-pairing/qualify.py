#!/usr/bin/env python3
"""Exercise published Core and Console packages on a disposable Ubuntu VM.

The only packet path is an isolated veth/network namespace. Credentials stay in
memory and the uploaded report contains no token, password, key, or host config.
"""

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import secrets
import tempfile
import time
import urllib.error
import urllib.request


HOST = runpy.run_path(str(Path(__file__).resolve().parents[2] / ".github/scripts/qualify-host-deb.py"))
BASE = "http://127.0.0.1:8787"
CONSOLE_STATE = Path("/var/lib/network-decode-firewall/credentials.json")


def check(ok, message):
    if not ok:
        raise HOST["ProbeError"](message)


def console(method, path, body=None, cookie=""):
    payload = json.dumps(body).encode() if body is not None else None
    headers = {"Origin": BASE}
    if cookie:
        headers["Cookie"] = cookie
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE + path, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            data = response.read()
            return response.status, json.loads(data) if data else None, response.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as error:
        return error.code, None, ""


def ready_console():
    for _ in range(30):
        try:
            status, _, _ = console("GET", "/health")
            if status == 200:
                return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise HOST["ProbeError"]("console did not become healthy")


def qualify(core_deb, console_bundle, report_path):
    run = HOST["run"]
    api = HOST["api"]
    checks = {}
    report = {
        "schema_version": 1,
        "core_package_sha256": hashlib.sha256(core_deb.read_bytes()).hexdigest(),
        "console_bundle_sha256": hashlib.sha256(console_bundle.read_bytes()).hexdigest(),
        "host": HOST["host_facts"](),
        "checks": checks,
        "result": "failed",
        "limitations": [
            "Disposable Ubuntu VM, isolated generic XDP veth; no physical NIC or throughput result.",
            "One exact source and one control source; no production reliability claim.",
            "Application bridge, user browser journey, and other Linux distributions are outside this pairing test.",
        ],
    }
    original_config = None
    core_started = False
    console_installed = False
    actions_enabled = False
    network_started = False
    token = ""
    stage = "preflight"
    try:
        check(HOST["MARKER"].is_file(), "disposable-host marker missing")
        check(run("id", "-u").stdout.strip() == "0", "root required")
        check(not HOST["CONFIG"].exists() and not HOST["STATE"].exists(), "preexisting HoneyMesh state")
        check(not Path("/opt/network-decode-firewall/current").exists(), "preexisting Console install")
        check(Path("/usr/bin/node").is_file(), "Node.js must be at /usr/bin/node")
        check(report["host"]["bpffs_mounted"], "BPF filesystem not mounted")
        check(run("dpkg-query", "-W", "honeymesh", check=False).returncode != 0, "preexisting Core package")

        stage = "install_core"
        core_started = True
        run("dpkg", "-i", str(core_deb), timeout=120)
        check(run("systemctl", "is-active", "--quiet", "honeymesh.service", check=False).returncode == 0,
              "Core service not active")
        original_config = HOST["CONFIG"].read_bytes()
        config = json.loads(original_config)
        check(config.get("interfaces") == [] and not config.get("trusted_network_sharing_enabled"),
              "Core did not start with safe sharing/interface defaults")
        token = HOST["ready_token"]()
        status, mode = api(token, "GET", "/api/mode")
        check(status == 200 and mode["mode"] == "TEST", "Core did not start in TEST")
        node_key_hash = hashlib.sha256(HOST["NODE_KEY"].read_bytes()).digest()
        token_hash = hashlib.sha256(token.encode()).digest()
        checks["core_safe_install_test_mode"] = True

        stage = "install_console"
        with tempfile.TemporaryDirectory(prefix="hm-console-pairing-") as folder:
            run("tar", "-xzf", str(console_bundle), "-C", folder)
            bundle = Path(folder) / "network-decode-firewall-console-0.2.1-beta.9"
            check(bundle.is_dir(), "published Console bundle layout changed")
            run("sh", str(bundle / "install-console.sh"), str(bundle), timeout=180)
            console_installed = True
            ready_console()
            bootstrap = json.loads(CONSOLE_STATE.read_text())["adminToken"]
            password = secrets.token_urlsafe(32)
            status, _, session_header = console("POST", "/api/account/setup", {
                "bootstrap_token": bootstrap, "username": "admin", "password": password,
            })
            check(status == 200 and session_header, "Console account setup failed")
            cookie = session_header.split(";", 1)[0]
            status, _, _ = console("POST", "/api/account/agent-token", {"token": token}, cookie)
            check(status == 200, "Console rejected pinned Core access")
            status, _, _ = console("GET", "/api/host/grants", cookie=cookie)
            check(status == 200, "Console protected Core read failed")
            checks["console_account_and_pinned_agent_read"] = True

            status, _, _ = console("POST", "/api/host/ban", {
                "ip": HOST["BLOCKED_IP"], "ttl_seconds": 60,
            }, cookie)
            check(status == 503, "Console allowed host write before opt-in")
            checks["console_default_read_only"] = True

            stage = "enable_controls"
            run("sh", str(bundle / "enable-host-actions.sh"), "ENABLE SCOPED HOST ACTIONS", timeout=90)
            actions_enabled = True
            status, _, _ = console("POST", "/api/host/ban", {
                "ip": HOST["BLOCKED_IP"], "ttl_seconds": 60,
            }, cookie)
            check(status == 409, "Console allowed a block in TEST")
            checks["console_test_rejects_block"] = True

            stage = "isolated_packet_effect"
            network_started = True
            HOST["create_isolated_network"]()
            check(HOST["wait_ping"](HOST["BLOCKED_IP"], True) and
                  HOST["wait_ping"](HOST["CONTROL_IP"], True), "isolated baseline traffic failed")
            config["interfaces"] = [HOST["HOST_IF"]]
            HOST["CONFIG"].write_text(json.dumps(config) + "\n")
            run("systemctl", "restart", "honeymesh.service")
            token = HOST["ready_token"]()
            for _ in range(20):
                if HOST["xdp_state"]()[1]:
                    break
                time.sleep(0.5)
            else:
                raise HOST["ProbeError"]("generic XDP did not attach to isolated veth")
            status, mode = api(token, "POST", "/api/mode", {"mode": "ENFORCE"})
            check(status == 200 and mode["mode"] == "ENFORCE", "Core ENFORCE transition failed")
            status, before = api(token, "GET", "/api/xdp/drop-totals")
            check(status == 200, "Core drop counters unavailable")
            status, created, _ = console("POST", "/api/host/ban", {
                "ip": HOST["BLOCKED_IP"], "ttl_seconds": 60,
            }, cookie)
            check(status == 200 and isinstance(created, dict) and
                  created.get("kernel_reconciled") is True and
                  str(created.get("grant_id", "")).startswith("firewall-console:"),
                  "Console grant did not reconcile")
            check(HOST["wait_ping"](HOST["BLOCKED_IP"], False), "Console-selected source was not dropped")
            check(HOST["wait_ping"](HOST["CONTROL_IP"], True), "control source was affected")
            status, after = api(token, "GET", "/api/xdp/drop-totals")
            check(status == 200 and after["ipv4"]["packets"] > before["ipv4"]["packets"],
                  "Core XDP drop counter did not rise")
            checks["console_grant_selected_source_drop_control_pass"] = True

            stage = "release_grant"
            status, released, _ = console("POST", "/api/host/release", {
                "ip": HOST["BLOCKED_IP"], "grant_id": created["grant_id"],
            }, cookie)
            check(status == 200 and released.get("grant_removed") is True and
                  released.get("kernel_reconciled") is True, "Console scoped release failed")
            check(HOST["wait_ping"](HOST["BLOCKED_IP"], True), "traffic did not recover after Console release")
            stage = "return_to_test"
            status, returned, _ = console("POST", "/api/host/test-mode", {"confirm": "RETURN TO TEST"}, cookie)
            check(status == 200 and returned.get("mode") == "TEST", "Console did not return Core to TEST")
            stage = "disable_controls"
            run("sh", str(bundle / "disable-host-actions.sh"), timeout=90)
            actions_enabled = False
            ready_console()
            stage = "confirm_read_only"
            status, _, _ = console("POST", "/api/host/ban", {
                "ip": HOST["BLOCKED_IP"], "ttl_seconds": 60,
            }, cookie)
            check(status == 503, "Console write path stayed open after disable")
            checks["scoped_release_test_recovery_and_write_disable"] = True

            stage = "restore_core_defaults"
            HOST["CONFIG"].write_bytes(original_config)
            original_config = None
            run("systemctl", "restart", "honeymesh.service")
            token = HOST["ready_token"]()
            check(not HOST["xdp_state"]()[0], "XDP stayed attached after config restore")
            check(hashlib.sha256(HOST["NODE_KEY"].read_bytes()).digest() == node_key_hash and
                  hashlib.sha256(token.encode()).digest() == token_hash, "Core identity changed after restart")
            checks["core_identity_preserved_and_xdp_detached"] = True
            stage = "remove_console"
            run("sh", str(bundle / "uninstall-console.sh"), str(bundle), timeout=90)
            console_installed = False
            checks["console_removed"] = True
        report["result"] = "passed"
    except HOST["ProbeError"] as error:
        report["failure"] = str(error)
    except Exception as error:
        report["failure"] = type(error).__name__
    finally:
        report["stage"] = stage
        cleanup_errors = []
        if token:
            try:
                status, _ = api(token, "POST", "/api/mode", {"mode": "TEST"})
                if status != 200:
                    cleanup_errors.append("Core TEST recovery unavailable")
            except (OSError, ValueError):
                cleanup_errors.append("Core TEST recovery request failed")
        if original_config is not None and HOST["CONFIG"].exists():
            HOST["CONFIG"].write_bytes(original_config)
            if run("systemctl", "restart", "honeymesh.service", check=False).returncode:
                cleanup_errors.append("Core config recovery failed")
        if actions_enabled:
            run("systemctl", "disable", "--now", "network-decode-firewall.service", check=False)
            cleanup_errors.append("Console action override needs review on disposable runner")
        if console_installed:
            run("systemctl", "disable", "--now", "network-decode-firewall.service", check=False)
        if network_started:
            run("ip", "link", "delete", HOST["HOST_IF"], check=False)
            run("ip", "netns", "delete", HOST["NETNS"], check=False)
        if core_started:
            run("systemctl", "disable", "--now", "honeymesh.service", check=False)
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            report["result"] = "failed"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"result": report["result"], "checks": checks,
                          "stage": stage, "failure": report.get("failure")}, sort_keys=True))
    return 0 if report["result"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-deb", required=True, type=Path)
    parser.add_argument("--console-bundle", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    return qualify(args.core_deb.resolve(strict=True), args.console_bundle.resolve(strict=True), args.report)


if __name__ == "__main__":
    raise SystemExit(main())
