import json
import os
import stat
import unittest

from graphenex.core.hrd.journal import (
    BackupManager,
    Journal,
    RunRecord,
    new_run_id,
    sha256_file,
    sha256_text,
)
from tests.support import isolated_state, workdir


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.state = isolated_state(self)
        self.journal = Journal()

    def test_creates_private_state_directory(self):
        self.assertTrue(self.state.exists())
        mode = stat.S_IMODE(self.state.stat().st_mode)
        self.assertEqual(mode, 0o700)

    def test_append_and_read(self):
        record = RunRecord(run_id="run-1", action="apply", module="ns/Mod", ok=True)
        self.journal.append(record)
        loaded = self.journal.records(refresh=True)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].run_id, "run-1")
        self.assertTrue(self.journal.path.exists())
        self.assertEqual(stat.S_IMODE(self.journal.path.stat().st_mode), 0o600)

    def test_hash_chain_is_valid_and_tamper_evident(self):
        for index in range(3):
            self.journal.append(
                RunRecord(run_id=f"run-{index}", action="apply", module="ns/Mod", ok=True)
            )
        ok, problems = self.journal.verify_chain()
        self.assertTrue(ok, problems)

        lines = self.journal.path.read_text().splitlines()
        data = json.loads(lines[1])
        data["module"] = "ns/Tampered"
        lines[1] = json.dumps(data)
        self.journal.path.write_text("\n".join(lines) + "\n")
        ok, problems = self.journal.verify_chain()
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in problem for problem in problems))

    def test_corrupt_line_is_skipped(self):
        self.journal.append(RunRecord(run_id="good", action="apply", module="m", ok=True))
        with open(self.journal.path, "a") as handle:
            handle.write("this is not json\n")
        records = self.journal.records(refresh=True)
        self.assertEqual([record.run_id for record in records], ["good"])

    def test_pending_and_reverted_state(self):
        apply_record = RunRecord(
            run_id="apply-1", action="apply", module="ns/Mod", ok=True
        )
        self.journal.append(apply_record)
        self.assertEqual(len(self.journal.pending()), 1)

        self.journal.append(
            RunRecord(
                run_id="revert-1",
                action="revert",
                module="ns/Mod",
                ok=True,
                parent_run_id="apply-1",
            )
        )
        self.assertEqual(self.journal.pending(), [])
        loaded = self.journal.get("apply-1")
        self.assertTrue(loaded.reverted)
        self.assertEqual(loaded.reverted_by, "revert-1")

    def test_failed_apply_is_not_pending(self):
        self.journal.append(RunRecord(run_id="failed", action="apply", module="m", ok=False))
        self.assertEqual(self.journal.pending(), [])

    def test_history_is_newest_first(self):
        for index in range(3):
            self.journal.append(RunRecord(run_id=f"r{index}", action="apply", module="m", ok=True))
        history = self.journal.history(2)
        self.assertEqual([record.run_id for record in history], ["r2", "r1"])


class BackupManagerTests(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.work = workdir(self)
        self.manager = BackupManager()

    def test_restores_new_file_by_deleting_it(self):
        new_file = self.work / "created.conf"
        entries = self.manager.capture("run-1", [str(new_file)])
        self.assertEqual(entries[0].kind, "missing")
        new_file.write_text("hardened")
        result = self.manager.restore(entries)[0]
        self.assertTrue(result["ok"])
        self.assertFalse(new_file.exists())

    def test_restores_content_and_mode(self):
        target = self.work / "config"
        target.write_text("original\n")
        os.chmod(target, 0o640)
        entries = self.manager.capture("run-2", [str(target)])
        target.write_text("hardened\n")
        os.chmod(target, 0o600)
        result = self.manager.restore(entries)[0]
        self.assertTrue(result["ok"])
        self.assertEqual(target.read_text(), "original\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

    def test_restores_directory_mode(self):
        directory = self.work / "dir"
        directory.mkdir(mode=0o755)
        entries = self.manager.capture("run-3", [str(directory)])
        os.chmod(directory, 0o700)
        self.manager.restore(entries)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)

    def test_globs_are_expanded(self):
        for name in ("a.conf", "b.conf"):
            (self.work / name).write_text(name)
        expanded = self.manager.expand([str(self.work / "*.conf")])
        self.assertEqual(len(expanded), 2)

    def test_symlink_is_restored(self):
        target = self.work / "target"
        target.write_text("x")
        link = self.work / "link"
        link.symlink_to(target)
        entries = self.manager.capture("run-4", [str(link)])
        link.unlink()
        self.manager.restore(entries)
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(target))

    def test_restore_refuses_paths_outside_the_backup_root(self):
        target = self.work / "file"
        target.write_text("data")
        entries = self.manager.capture("run-5", [str(target)])
        entries[0].stored = "/etc/passwd"
        result = self.manager.restore(entries)[0]
        self.assertFalse(result["ok"])
        self.assertIn("outside the backup root", result["error"])

    def test_run_id_format(self):
        run_id = new_run_id()
        self.assertIn("T", run_id)
        self.assertEqual(len(run_id), len("20260101T000000Z-") + 8)

    def test_sha256_helpers(self):
        target = self.work / "hashed"
        target.write_text("abc")
        self.assertEqual(sha256_text("abc"), sha256_file(target))
