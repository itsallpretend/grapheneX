import os
import shlex
import stat
import unittest

from graphenex.core.hrd import HardenMethod
from graphenex.core.hrd.journal import Journal
from graphenex.core.hrd.recovery import resolve_runs, revert_record
from graphenex.core.utils import privileges
from tests.support import isolated_state, workdir


class HardenMethodTests(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.work = workdir(self)
        self.journal = Journal()

    def make_module(self, **overrides):
        target = self.work / "config.conf"
        target.write_text("Setting = insecure\n")
        module_kwargs = dict(
            namespace="test",
            name="Test_Setting",
            desc="Test module that rewrites a temporary configuration file.",
            command="printf 'Setting = secure\\n' > " + shlex.quote(str(target)),
            check="grep -q 'Setting = secure' " + shlex.quote(str(target)),
            revert="printf 'Setting = insecure\\n' > " + shlex.quote(str(target)),
            files=[str(target)],
            shell=True,
            target_os="linux",
            cis=["1.1.1"],
            risk="low",
            require_superuser=False,
        )
        module_kwargs.update(overrides)
        module = HardenMethod(**module_kwargs)
        return module, target

    def test_metadata(self):
        module, _ = self.make_module()
        self.assertEqual(module.qualified_name, "test/Test_Setting")
        self.assertTrue(module.revertible)
        self.assertEqual(module.revert_strategy, "command+files")
        self.assertEqual(module.to_dict()["check"], module.check_command)

    def test_check_reports_drift_then_compliance(self):
        module, _ = self.make_module()
        self.assertFalse(module.check().ok)
        module.apply(journal=self.journal)
        self.assertTrue(module.check().ok)

    def test_apply_records_run_and_backups(self):
        module, target = self.make_module()
        outcome = module.apply(journal=self.journal)
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.journaled)
        self.assertTrue(outcome.verified)
        self.assertEqual(target.read_text(), "Setting = secure\n")

        record = self.journal.get(outcome.run_id)
        self.assertIsNotNone(record)
        self.assertEqual(record.module, "test/Test_Setting")
        self.assertEqual(record.action, "apply")
        self.assertTrue(record.pre_state == "" or isinstance(record.pre_state, str))
        self.assertEqual(len(record.backups), 1)
        self.assertIn("post_hashes", record.extra)

    def test_revert_restores_original_content(self):
        module, target = self.make_module()
        outcome = module.apply(journal=self.journal)
        revert = module.revert(run_id=outcome.run_id, journal=self.journal)
        self.assertTrue(revert.ok, revert.to_dict())
        self.assertTrue(revert.verified)
        self.assertEqual(target.read_text(), "Setting = insecure\n")
        self.assertEqual(self.journal.pending(), [])

    def test_double_revert_is_refused(self):
        module, _ = self.make_module()
        outcome = module.apply(journal=self.journal)
        module.revert(run_id=outcome.run_id, journal=self.journal)
        second = module.revert(run_id=outcome.run_id, journal=self.journal)
        self.assertFalse(second.ok)
        self.assertIn("already reverted", second.error)

    def test_revert_without_module_definition(self):
        """Revert must work when the module was deleted from modules.json."""

        module, target = self.make_module()
        outcome = module.apply(journal=self.journal)
        record = self.journal.get(outcome.run_id)
        del module
        revert = revert_record(record, journal=self.journal)
        self.assertTrue(revert.ok, revert.to_dict())
        self.assertEqual(target.read_text(), "Setting = insecure\n")

    def test_dry_run_changes_nothing(self):
        module, target = self.make_module()
        outcome = module.apply(dry_run=True, journal=self.journal)
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.dry_run)
        self.assertFalse(outcome.journaled)
        self.assertEqual(target.read_text(), "Setting = insecure\n")
        self.assertEqual(self.journal.records(refresh=True), [])

    def test_already_compliant_is_skipped(self):
        module, target = self.make_module(command="true", check="true")
        outcome = module.apply(journal=self.journal)
        self.assertTrue(outcome.already_compliant)
        self.assertFalse(outcome.journaled)
        self.assertEqual(self.journal.records(refresh=True), [])

    def test_force_applies_even_when_compliant(self):
        module, target = self.make_module(check="true")
        outcome = module.apply(force=True, journal=self.journal)
        self.assertFalse(outcome.already_compliant)
        self.assertTrue(outcome.journaled)
        self.assertEqual(target.read_text(), "Setting = secure\n")

    def test_unrevertible_module_is_refused(self):
        module, _ = self.make_module()
        module.revert_command = ""
        module.files = []
        self.assertFalse(module.revertible)
        with self.assertRaises(PermissionError):
            module.apply(journal=self.journal)
        outcome = module.apply(journal=self.journal, allow_unrevertible=True)
        self.assertTrue(outcome.ok)

    def test_irreversible_module_needs_opt_in(self):
        module, _ = self.make_module()
        module.revert_command = ""
        module.files = []
        module.irreversible = True
        module.irreversible_reason = "test fixture"
        with self.assertRaises(PermissionError):
            module.apply(journal=self.journal)
        outcome = module.apply(journal=self.journal, allow_irreversible=True)
        self.assertTrue(outcome.ok)

    @unittest.skipIf(privileges.is_elevated(), "must run unprivileged")
    def test_superuser_module_is_refused_without_root(self):
        module, _ = self.make_module(require_superuser=True)
        with self.assertRaises(PermissionError) as caught:
            module.apply(journal=self.journal)
        self.assertIn("privileges", str(caught.exception))

    def test_failed_apply_is_journaled_and_not_pending(self):
        module, _ = self.make_module(
            command="sh -c 'exit 4'", check="false", revert="true"
        )
        outcome = module.apply(journal=self.journal)
        self.assertFalse(outcome.ok)
        self.assertTrue(outcome.journaled)
        self.assertEqual(self.journal.pending(), [])
        record = self.journal.get(outcome.run_id)
        self.assertEqual(record.returncode, 4)
        # An explicit run id can still be reverted (partial change clean-up).
        revert = module.revert(run_id=outcome.run_id, journal=self.journal)
        self.assertTrue(revert.ok)

    def test_file_only_module_removes_created_file(self):
        created = self.work / "new-drop-in.conf"
        module = HardenMethod(
            namespace="test",
            name="Create_Drop_In",
            desc="Creates a new configuration drop-in file.",
            command="printf 'x=1\n' > " + shlex.quote(str(created)),
            check="test -f " + shlex.quote(str(created)),
            files=[str(created)],
            shell=True,
            target_os="linux",
            require_superuser=False,
        )
        self.assertEqual(module.revert_strategy, "files")
        outcome = module.apply(journal=self.journal)
        self.assertTrue(outcome.ok)
        self.assertTrue(created.exists())
        revert = module.revert(run_id=outcome.run_id, journal=self.journal)
        self.assertTrue(revert.ok)
        self.assertFalse(created.exists())

    def test_glob_backups_restore_every_match(self):
        directory = self.work / "keys"
        directory.mkdir()
        files = []
        for name in ("key_a", "key_b"):
            path = directory / name
            path.write_text("secret")
            os.chmod(path, 0o644)
            files.append(path)
        module = HardenMethod(
            namespace="test",
            name="Tighten_Keys",
            desc="Tightens permissions on key files matched by a glob.",
            command="chmod 600 " + str(directory / "key_*"),
            check="find " + str(directory) + " -name 'key_*' -perm /077 | grep -q . && exit 1; exit 0",
            files=[str(directory / "key_*")],
            shell=True,
            target_os="linux",
            require_superuser=False,
        )
        outcome = module.apply(journal=self.journal)
        self.assertTrue(outcome.ok)
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        module.revert(run_id=outcome.run_id, journal=self.journal)
        for path in files:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_resolve_runs(self):
        first, _ = self.make_module(name="First_Module")
        second, _ = self.make_module(name="Second_Module")
        first_apply = first.apply(journal=self.journal, force=True)
        second_apply = second.apply(journal=self.journal, force=True)
        self.assertEqual(
            [record.run_id for record in resolve_runs(self.journal, "last")],
            [second_apply.run_id],
        )
        self.assertEqual(len(resolve_runs(self.journal, "all")), 2)
        self.assertEqual(len(resolve_runs(self.journal, first_apply.run_id)), 1)
        self.assertEqual(len(resolve_runs(self.journal, "test/First_Module")), 1)
