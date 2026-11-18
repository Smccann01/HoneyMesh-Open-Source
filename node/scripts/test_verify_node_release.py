"""Exercise signed release verification with a disposable QA key."""

import json
import hashlib
import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from verify_node_release import verify_release


ROOT = Path(__file__).resolve().parents[1]


class SignedNodeReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="hm-node-sign-qa-")
        cls.base = Path(cls.temp.name)
        cls.home = cls.base / "gnupg"
        cls.home.mkdir(mode=0o700)
        os.chmod(cls.home, 0o700)
        cls.gpg = ["gpg", "--batch", "--homedir", str(cls.home)]
        subprocess.run(cls.gpg + ["--passphrase", "", "--quick-generate-key", "Node QA <qa@example.test>",
                                  "ed25519", "sign", "1d"], check=True, capture_output=True)
        keys = subprocess.check_output(cls.gpg + ["--with-colons", "--fingerprint", "--list-keys"], text=True)
        cls.fingerprint = next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))
        cls.public_key = cls.base / "public.asc"
        cls.public_key.write_bytes(subprocess.check_output(cls.gpg + ["--armor", "--export", cls.fingerprint]))
        cls.manifest = cls.base / "manifest.json"
        record = json.loads((ROOT / "release-signing/NODE-RELEASE-MANIFEST.json").read_text())
        record["publisher_fingerprint"] = cls.fingerprint
        cls.manifest.write_text(json.dumps(record, indent=2) + "\n")
        cls.signature = cls.base / "manifest.asc"
        subprocess.run(cls.gpg + ["--armor", "--detach-sign", "--output", str(cls.signature), str(cls.manifest)],
                       check=True, capture_output=True)
        cls.guard = ROOT / "dist/honeymesh-node-guard-0.1.2.tgz"
        cls.pro = ROOT / "dist/node-pro-package-candidate-2/honeymesh_2.3.6-rc4-nodepro2_amd64.deb"

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_exact_signed_artifacts_verify(self):
        record = verify_release(self.manifest, self.signature, self.public_key, self.guard, self.pro,
                                expected_fingerprint=self.fingerprint)
        self.assertEqual(len(record["artifacts"]), 2)

    def test_wrong_publisher_and_modified_artifact_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "pinned key"):
            verify_release(self.manifest, self.signature, self.public_key, self.guard, self.pro,
                           expected_fingerprint="A" * 40)
        changed = self.base / self.guard.name
        changed.write_bytes(self.guard.read_bytes() + b"modified")
        with self.assertRaisesRegex(ValueError, "node_guard artifact"):
            verify_release(self.manifest, self.signature, self.public_key, changed, self.pro,
                           expected_fingerprint=self.fingerprint)

    def test_modified_manifest_is_rejected_by_signature(self):
        changed = self.base / "changed.json"
        record = json.loads(self.manifest.read_text())
        record["artifacts"][0]["version"] = "0.1.3"
        changed.write_text(json.dumps(record))
        with self.assertRaises(subprocess.CalledProcessError):
            verify_release(changed, self.signature, self.public_key, self.guard, self.pro,
                           expected_fingerprint=self.fingerprint)

    def test_signed_bundle_builder_embeds_the_verified_manifest(self):
        core_name = "honeymesh_2.3.6-rc4-Iron-Hive_amd64.deb"
        core = self.base / core_name
        quickstart = self.base / "Core-quickstart.md"
        with tarfile.open(ROOT / "dist/customer-bundles-2/HoneyMesh-Node-Pro-pilot-rc4-amd64.tar.gz", "r:gz") as archive:
            for member in archive:
                name = Path(member.name).name
                if name == core_name:
                    core.write_bytes(archive.extractfile(member).read())
                elif name == quickstart.name:
                    quickstart.write_bytes(archive.extractfile(member).read())
        core_manifest = self.base / "core.json"
        core_manifest.write_text(json.dumps({"artifacts": [{"path": core_name,
            "sha256": hashlib.sha256(core.read_bytes()).hexdigest()}]}))
        core_signature = self.base / "core.asc"
        subprocess.run(self.gpg + ["--armor", "--detach-sign", "--output", str(core_signature), str(core_manifest)],
                       check=True, capture_output=True)
        spec = importlib.util.spec_from_file_location("build_customer_bundles", ROOT / "scripts/build-customer-bundles.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        output = self.base / "signed-bundles"
        argv = ["build-customer-bundles.py", "--core-deb", str(core), "--core-manifest", str(core_manifest),
                "--core-signature", str(core_signature), "--publisher-key", str(self.public_key),
                "--core-quickstart", str(quickstart), "--node-pro-deb", str(self.pro),
                "--node-manifest", str(self.manifest), "--node-signature", str(self.signature),
                "--signed-install-guide", str(ROOT / "CUSTOMER_INSTALL_SIGNED_CANDIDATE.md"),
                "--output", str(output)]
        with patch.object(builder, "FINGERPRINT", self.fingerprint), patch.object(sys, "argv", argv):
            builder.main()
        record = json.loads((output / "BUNDLE-MANIFEST.json").read_text())
        self.assertIn("publisher-signed paid beta", record["status"])
        for bundle in record["bundles"]:
            archive_path = output / bundle["name"]
            self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), bundle["sha256"])
            with tarfile.open(archive_path, "r:gz") as archive:
                names = {Path(member.name).name for member in archive}
            self.assertTrue({"Node-manifest.json", "Node-manifest.asc", "Node-publisher-public.asc"} <= names)


if __name__ == "__main__":
    unittest.main()
