import unittest

from graphenex.core.hrd.schema import (
    ModuleIssue,
    ModuleValidationError,
    normalize_module,
)

def base_module(**overrides):
    module = {
        "name": "Test_Module",
        "desc": "A test module used by the unit tests.",
        "command": "echo apply",
        "check": "true",
        "revert": "echo revert",
        "target_os": "linux",
    }
    module.update(overrides)
    return module


class NormalizeModuleTests(unittest.TestCase):
    def test_valid_module_gets_defaults(self):
        module = normalize_module(base_module())
        self.assertFalse(module["shell"])
        self.assertEqual(module["timeout"], 120)
        self.assertEqual(module["risk"], "medium")
        self.assertTrue(module["revertible"] if "revertible" in module else True)
        self.assertEqual(module["files"], [])
        self.assertFalse(module["irreversible"])

    def test_legacy_boolean_strings_are_accepted(self):
        module = normalize_module(
            base_module(require_superuser="True", require_restart="False")
        )
        self.assertTrue(module["require_superuser"])
        self.assertFalse(module["require_restart"])

    def test_revert_is_mandatory(self):
        with self.assertRaises(ModuleValidationError) as caught:
            normalize_module(base_module(revert=""))
        self.assertTrue(any(issue.field == "revert" for issue in caught.exception.issues))

    def test_files_can_replace_a_revert_command(self):
        module = normalize_module(base_module(revert="", files=["/etc/hosts"]))
        self.assertEqual(module["revert"], "")
        self.assertEqual(module["files"], ["/etc/hosts"])

    def test_irreversible_requires_reason(self):
        with self.assertRaises(ModuleValidationError) as caught:
            normalize_module(base_module(revert="", irreversible=True))
        self.assertTrue(
            any(issue.field == "irreversible_reason" for issue in caught.exception.issues)
        )

    def test_irreversible_with_reason_is_a_warning(self):
        module = normalize_module(
            base_module(revert="", irreversible=True, irreversible_reason="by design")
        )
        self.assertTrue(module["irreversible"])
        self.assertTrue(any(issue.severity == "warning" for issue in module["issues"]))

    def test_invalid_name(self):
        for name in ("1bad", "has space", "a", "bad-name"):
            with self.assertRaises(ModuleValidationError):
                normalize_module(base_module(name=name))

    def test_invalid_target_os(self):
        with self.assertRaises(ModuleValidationError) as caught:
            normalize_module(base_module(target_os="solaris"))
        self.assertTrue(
            any(issue.field == "target_os" for issue in caught.exception.issues)
        )

    def test_unknown_fields_warn(self):
        module = normalize_module(base_module(comandd="typo"))
        self.assertTrue(any(issue.field == "comandd" for issue in module["issues"]))

    def test_timeout_bounds(self):
        for timeout in (0, -5, 100000):
            with self.assertRaises(ModuleValidationError):
                normalize_module(base_module(timeout=timeout))

    def test_relative_file_paths_are_rejected(self):
        with self.assertRaises(ModuleValidationError):
            normalize_module(base_module(files=["etc/passwd"]))

    def test_path_traversal_is_rejected(self):
        with self.assertRaises(ModuleValidationError):
            normalize_module(base_module(files=["/etc/../etc/shadow"]))

    def test_broad_snapshot_paths_are_rejected(self):
        for path in ("/etc", "/usr", "/home", "/var"):
            with self.assertRaises(ModuleValidationError):
                normalize_module(base_module(files=[path]))

    def test_invalid_cis_control(self):
        with self.assertRaises(ModuleValidationError):
            normalize_module(base_module(cis=["CIS 5.2.8"]))

    def test_invalid_nist_control(self):
        with self.assertRaises(ModuleValidationError):
            normalize_module(base_module(nist=["ac17"]))

    def test_shell_commands_may_contain_pipes(self):
        normalize_module(base_module(command="cat /etc/hosts | head", shell=True))
        module = normalize_module(base_module(command="cat /etc/hosts | head", shell=False))
        self.assertTrue(
            any("metacharacters" in issue.message for issue in module["issues"])
        )

    def test_issue_str_is_readable(self):
        issue = ModuleIssue("Mod", "field", "is broken")
        self.assertIn("Mod", str(issue))
        self.assertIn("broken", str(issue))
