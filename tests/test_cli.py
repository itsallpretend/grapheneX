"""End-to-end tests for the non-interactive CLI (no third-party deps)."""

import json
import os
import subprocess
import sys
import unittest

from tests.support import REPO_ROOT, workdir


class BatchCliTests(unittest.TestCase):
    def setUp(self):
        self.state = workdir(self)
        self.work = workdir(self)
        self.target = self.work / "graphenex-test.conf"
        self.modules_file = self.work / "modules.json"
        self.modules_file.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "test": [
                        {
                            "name": "Test_Drop_In",
                            "desc": "Test module used by the CLI tests.",
                            "command": f"printf 'hardened\\n' > {self.target}",
                            "check": f"grep -qx hardened {self.target}",
                            "revert": f"rm -f {self.target}",
                            "files": [str(self.target)],
                            "shell": True,
                            "target_os": "linux",
                            "require_superuser": False,
                            "require_restart": False,
                            "risk": "low",
                            "cis": ["1.1.1"],
                            "nist": ["CM-6"],
                        }
                    ],
                    "presets": [
                        {
                            "name": "test_preset",
                            "desc": "A preset for the CLI tests.",
                            "risk": "low",
                            "target_os": "linux",
                            "modules": ["test/Test_Drop_In"],
                        }
                    ],
                }
            )
        )

    def run_cli(self, *arguments, expect=0):
        env = dict(os.environ)
        env.update(
            {
                "PYTHONPATH": str(REPO_ROOT),
                "GRAPHENEX_STATE_DIR": str(self.state),
                "GRAPHENEX_MODULES": str(self.modules_file),
                "NO_COLOR": "1",
                "GRAPHENEX_ASSUME_YES": "1",
            }
        )
        completed = subprocess.run(
            [sys.executable, "-m", "graphenex", *arguments],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        self.assertEqual(
            completed.returncode,
            expect,
            f"exit {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def test_version(self):
        output = self.run_cli("--version").stdout
        self.assertIn("grapheneX v", output)

    def test_validate_json(self):
        payload = json.loads(self.run_cli("--validate", "--json").stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["errors"], [])
        self.assertEqual(payload["module_count"], 1)

    def test_list_json(self):
        payload = json.loads(self.run_cli("--list", "--json").stdout)
        self.assertEqual(payload["count"], 1)
        module = payload["modules"][0]
        self.assertEqual(module["qualified_name"], "test/Test_Drop_In")
        self.assertTrue(module["revertible"])
        self.assertEqual(module["revert_strategy"], "command+files")

    def test_list_table(self):
        output = self.run_cli("--list").stdout
        self.assertIn("test/Test_Drop_In", output)
        self.assertIn("Description", output)

    def test_apply_check_history_revert_round_trip(self):
        apply_payload = json.loads(self.run_cli("--apply", "all", "--json").stdout)
        self.assertTrue(apply_payload["ok"])
        self.assertTrue(self.target.exists())
        run_id = apply_payload["results"][0]["run_id"]
        self.assertTrue(run_id)

        check_payload = json.loads(self.run_cli("--check", "all", "--json").stdout)
        self.assertTrue(check_payload["ok"])
        self.assertEqual(check_payload["summary"]["compliant"], 1)

        history_payload = json.loads(self.run_cli("--history", "--json").stdout)
        self.assertTrue(history_payload["chain_ok"])
        self.assertEqual(history_payload["chain_problems"], [])
        actions = [record["action"] for record in history_payload["records"]]
        self.assertIn("apply", actions)
        self.assertIn("audit", actions)

        revert_payload = json.loads(self.run_cli("--revert", "all", "--json").stdout)
        self.assertTrue(revert_payload["ok"])
        self.assertFalse(self.target.exists())

        drift_payload = self.run_cli("--check", "all", "--json", expect=1)
        self.assertFalse(json.loads(drift_payload.stdout)["ok"])

    def test_revert_by_run_id(self):
        payload = json.loads(self.run_cli("--apply", "test/Test_Drop_In", "--json").stdout)
        run_id = payload["results"][0]["run_id"]
        revert = json.loads(self.run_cli("--revert", run_id, "--json").stdout)
        self.assertTrue(revert["ok"])
        self.assertEqual(revert["results"][0]["run_id"], run_id)

    def test_dry_run_does_not_touch_the_system(self):
        payload = json.loads(self.run_cli("--apply", "all", "--json", "--dry-run").stdout)
        self.assertTrue(payload["ok"])
        self.assertFalse(self.target.exists())
        self.assertEqual(self.run_cli("--history", "--json").stdout.count("\"records\""), 1)

    def test_unknown_target_is_a_usage_error(self):
        completed = self.run_cli("--apply", "does/notexist", expect=2)
        self.assertIn("unknown", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_revert_without_pending_runs_is_a_noop(self):
        payload = json.loads(self.run_cli("--revert", "last", "--json").stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["results"], [])
