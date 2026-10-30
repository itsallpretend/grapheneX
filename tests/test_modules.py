"""Compliance gates for the shipped modules.json."""

import json
import unittest

from graphenex.core.hrd.schema import validate_modules_file
from tests.support import MODULES_FILE


class ShippedModulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = validate_modules_file(MODULES_FILE)
        cls.data = json.loads(MODULES_FILE.read_text())
        cls.modules = [
            module
            for namespace, definitions in cls.report.modules.items()
            for module in definitions.values()
        ]

    def test_file_is_valid_without_errors_or_warnings(self):
        self.assertTrue(self.report.ok, [str(issue) for issue in self.report.errors])
        self.assertEqual([str(issue) for issue in self.report.warnings], [])

    def test_schema_version(self):
        self.assertEqual(self.data.get("schema_version"), 2)

    def test_every_module_has_an_audit_command(self):
        for module in self.modules:
            self.assertTrue(module["check"].strip(), module["name"])

    def test_every_module_can_be_reverted(self):
        for module in self.modules:
            self.assertTrue(
                module["revert"] or module["files"] or module["irreversible"],
                f"{module['name']} has no revert mechanism",
            )

    def test_every_module_is_mapped_to_a_control(self):
        for module in self.modules:
            self.assertTrue(module["cis"], f"{module['name']} has no CIS mapping")
            self.assertTrue(module["nist"], f"{module['name']} has no NIST mapping")

    def test_risk_levels_are_set(self):
        for module in self.modules:
            self.assertIn(module["risk"], ("low", "medium", "high", "critical"))

    def test_shell_is_only_used_when_required(self):
        for module in self.modules:
            if module["shell"]:
                continue
            for field in ("command", "check", "revert", "probe"):
                value = module.get(field) or ""
                for marker in ("|", ">", "<", "&&", ";", "`", "$("):
                    self.assertNotIn(
                        marker,
                        value,
                        f"{module['name']}.{field} needs 'shell': true",
                    )

    def test_module_names_are_unique_per_namespace(self):
        for namespace, definitions in self.report.modules.items():
            names = [name.lower() for name in definitions]
            self.assertEqual(len(names), len(set(names)), namespace)

    def test_both_platforms_are_covered(self):
        targets = {module["target_os"] for module in self.modules}
        self.assertEqual(targets, {"linux", "win"})
        self.assertGreaterEqual(
            sum(1 for module in self.modules if module["target_os"] == "linux"), 40
        )
        self.assertGreaterEqual(
            sum(1 for module in self.modules if module["target_os"] == "win"), 20
        )

    def test_module_library_is_at_least_as_large_as_before(self):
        # The 1.7 release shipped 77 one-line modules without audit/revert.
        self.assertGreaterEqual(len(self.modules), 77)

    def test_presets_reference_existing_modules(self):
        self.assertTrue(self.report.presets)
        for preset in self.report.presets:
            self.assertIn(preset["target_os"], ("linux", "win"))
            self.assertTrue(preset.get("desc"))
            self.assertIn(preset.get("risk"), ("low", "medium", "high"))
            for member in preset["modules"]:
                namespace, _, name = member.partition("/")
                self.assertIn(namespace, self.report.modules)
                if name.lower() != "all":
                    self.assertIn(name, self.report.modules[namespace])

    def test_no_module_modifies_dangerous_roots(self):
        for module in self.modules:
            for path in module["files"]:
                self.assertNotIn(path.rstrip("/"), ("/", "/etc", "/usr", "/home"))
