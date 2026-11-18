#!/usr/bin/env python3
"""Make an isolated, keygen-free agent integration tree from verified rc2 source."""

import hashlib
import shutil
import sys
import tarfile
from pathlib import Path

SOURCE_SHA256 = "6c020f71f6a54c5566bfd1336d8f04ffc3dcb20e2a9de1a246f513847c245266"
PREFIX = "HoneyMesh-2.3.6-rc2/"
ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"unexpected release source shape: {path.name}")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare.py VERIFIED_SOURCE_TAR OUTPUT_DIRECTORY")
    archive_path, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise SystemExit("2.3.6-rc2 source checksum mismatch")
    if output.exists():
        raise SystemExit("output already exists; choose a fresh directory")
    output.mkdir(parents=True, mode=0o700)
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive:
                if member.name == PREFIX.rstrip("/") and member.isdir():
                    continue
                if not member.name.startswith(PREFIX):
                    raise SystemExit("unexpected archive root")
                relative = Path(member.name[len(PREFIX):])
                if not relative.parts or ".." in relative.parts or relative.is_absolute():
                    continue
                if relative.parts[:2] == ("tools", "license-keygen"):
                    continue
                if not member.isdir() and not member.isfile():
                    raise SystemExit("unexpected archive member type")
                target = output / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as src, target.open("wb") as dest:
                    shutil.copyfileobj(src, dest)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
        if (output / "tools/license-keygen").exists():
            raise SystemExit("keygen was not excluded")
        (output / "internal/agentbridge").mkdir(parents=True)
        shutil.copy2(ROOT / "agentbridge/bridge.go", output / "internal/agentbridge/bridge.go")
        shutil.copy2(ROOT / "agent-integration/node_edge_integration.go", output / "node_edge_integration.go")
        shutil.copy2(ROOT / "agent-integration/node_edge_integration_test.go", output / "node_edge_integration_test.go")

        main_go = output / "main.go"
        replace_once(main_go, "\tinitDB()\n", "\tinitDB()\n\tif err := initNodeEdgeAudit(); err != nil { log.Fatalf(\"[NODE_EDGE] audit init: %v\", err) }\n")
        replace_once(main_go, "\t// 12. GRACEFUL SHUTDOWN", "\tif err := startNodeEdgeBridge(shutdown); err != nil { log.Fatalf(\"[NODE_EDGE] bridge startup: %v\", err) }\n\n\t// 12. GRACEFUL SHUTDOWN")

        runtime = output / "runtime.go"
        replace_once(runtime, "func startBanCleanup(shutdown chan struct{}) {\n\tticker := time.NewTicker(1 * time.Minute)",
                     "func startBanCleanup(shutdown chan struct{}) {\n\tticker := time.NewTicker(5 * time.Second)")
        replace_once(runtime, "\t\tif now.After(exp) {\n\t\t\tunbanIP(ip)",
                     "\t\tif now.After(exp) {\n\t\t\tbanMetaMu.Lock()\n\t\t\tisNodeEdge := banMeta[ip].Category == nodeEdgeCategory\n\t\t\tbanMetaMu.Unlock()\n\t\t\tif isNodeEdge {\n\t\t\t\tif err := nodeEdgeRemove(ip); err != nil { log.Printf(\"[NODE_EDGE] expiry release failed ip=%s: %v\", ip, err); continue }\n\t\t\t\tmarkNodeEdgeExpired(ip)\n\t\t\t} else {\n\t\t\t\tunbanIP(ip)\n\t\t\t}")

        globals_go = output / "globals.go"
        replace_once(globals_go, "func SetMode(m ModeType) {\n\tModeMu.Lock()\n\tGlobalMode = m\n\tModeMu.Unlock()\n}",
                     "func SetMode(m ModeType) error {\n\tModeMu.Lock()\n\tGlobalMode = m\n\tModeMu.Unlock()\n\tif m != ModeEnforce { return releaseNodeEdgeBlocks(\"mode_change\") }\n\treturn nil\n}")

        trust = output / "trust.go"
        replace_once(trust, "\tunbanIP(ip)\n\tremoveBan(ip)",
                     "\tunbanIP(ip)\n\tmarkNodeEdgeReleased(ip, \"operator_allow\")\n\tremoveBan(ip)")

        dashboard = output / "dashboard.go"
        replace_once(dashboard, "\tunbanIP(req.IP)\n\tremoveBan(req.IP)",
                     "\tunbanIP(req.IP)\n\tmarkNodeEdgeReleased(req.IP, \"operator_release\")\n\tremoveBan(req.IP)")
        replace_once(dashboard, "\tcase \"TEST\":\n\t\tSetMode(ModeTest)\n\tcase \"ENFORCE\", \"LOCKDOWN\":\n\t\tif m.Mode == \"ENFORCE\" {\n\t\t\tSetMode(ModeEnforce)\n\t\t} else {\n\t\t\tSetMode(ModeLockdown)\n\t\t}\n\t}",
                     "\tcase \"TEST\":\n\t\tif err := SetMode(ModeTest); err != nil { http.Error(w, \"app rule release failed: \"+err.Error(), http.StatusInternalServerError); return }\n\tcase \"ENFORCE\":\n\t\tif err := SetMode(ModeEnforce); err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }\n\tcase \"LOCKDOWN\":\n\t\tif err := SetMode(ModeLockdown); err != nil { http.Error(w, \"app rule release failed: \"+err.Error(), http.StatusInternalServerError); return }\n\tdefault:\n\t\thttp.Error(w, \"invalid mode\", http.StatusBadRequest); return\n\t}")
        tui = output / "tui.go"
        replace_once(tui, "\t\tcase \"test\":\n\t\t\tSetMode(ModeTest)\n\t\tcase \"enforce\":\n\t\t\tSetMode(ModeEnforce)\n\t\tcase \"lockdown\":\n\t\t\tSetMode(ModeLockdown)",
                     "\t\tcase \"test\":\n\t\t\tif err := SetMode(ModeTest); err != nil { fmt.Printf(\"[NODE_EDGE] app rule release failed: %v\\n\", err) }\n\t\tcase \"enforce\":\n\t\t\tif err := SetMode(ModeEnforce); err != nil { fmt.Printf(\"[NODE_EDGE] mode change failed: %v\\n\", err) }\n\t\tcase \"lockdown\":\n\t\t\tif err := SetMode(ModeLockdown); err != nil { fmt.Printf(\"[NODE_EDGE] app rule release failed: %v\\n\", err) }")
        print(f"prepared sanitized agent tree: {output}")
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__ == "__main__":
    main()
