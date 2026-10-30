"""Interactive shell commands."""

from __future__ import annotations

import random

from graphenex.core.cli import prompts
from graphenex.core.cli.help import Help
from graphenex.core.cli.table import render_table
from graphenex.core.hrd.journal import Journal
from graphenex.core.hrd.recovery import resolve_runs, revert_record
from graphenex.core.hrd.schema import NAME_RE
from graphenex.core.utils import helpers
from graphenex.core.utils.helpers import check_os, get_presets, get_modules
from graphenex.core.utils.logcl import GraphenexLogger

logger = GraphenexLogger(__name__)

MODULE_FIELDS = [
    "desc",
    "command",
    "check",
    "revert",
    "files",
    "shell",
    "require_superuser",
    "require_restart",
    "risk",
    "cis",
    "nist",
]


def _split_list(value):
    return [item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()]


def _as_bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


class ShellCommands(Help):
    #: Set by :class:`graphenex.core.cli.shell.Shell`.
    options = {}

    # -- navigation ------------------------------------------------------
    def do_switch(self, arg):
        """Switch between modules or namespaces"""

        if not arg:
            logger.warn("'switch' command takes 1 argument.")
            return
        arg = arg.lower()
        if arg in self.modules.keys():
            logger.info(
                f'Switched to "{arg}" namespace.'
                " Use 'list' command to see available modules."
            )
            self.namespace = arg
            self.module = ""
        else:
            self.do_use(arg)

    def complete_switch(self, text, line, begidx, endidx):
        """Complete switch command"""

        avb_namespaces = [i.lower() for i in self.modules.keys()]
        mline = line.lower().partition(" ")[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in avb_namespaces if s.startswith(mline)]

    def do_use(self, arg):
        """Use the hardening module"""

        if not arg:
            logger.warn("'use' command takes 1 argument.")
            return
        if "/" in arg and arg.split("/")[0].lower() in self.modules.keys():
            self.namespace = arg.split("/")[0].lower()
            arg = arg.split("/")[1]

        def select_module_msg():
            logger.info(
                f'"{self.module}" module selected. Use \'harden\' to apply it, '
                "'check' to audit it or 'info' for details."
            )

        module_found = False
        if self.namespace:
            for name in self.modules[self.namespace]:
                if arg.lower() == name.lower():
                    module_found = True
                    self.module = name
                    select_module_msg()
        else:
            for namespace, definitions in self.modules.items():
                for name in definitions:
                    if arg.lower() == name.lower():
                        module_found = True
                        self.module = name
                        self.namespace = namespace
                        select_module_msg()
        if not module_found:
            logger.error(f'No module/namespace named "{arg}".')

    def complete_use(self, text, line, begidx, endidx):
        """Complete use command"""

        avb_modules = self.modules.get(self.namespace)
        if avb_modules is None:
            avb_modules = []
            for key, value in self.modules.items():
                for name in value:
                    avb_modules.append(f"{key}/{name}")
        else:
            avb_modules = list(avb_modules)
        mline = line.lower().partition(" ")[2]
        if "/" in mline:
            namespace, _, name = mline.partition("/")
            mline = namespace.lower() + "/" + name.title()
        offs = len(mline) - len(text)
        comp_text = [s[offs:] for s in avb_modules if s.lower().startswith(mline.lower())]
        if len(comp_text) == 0:
            avb_modules = [
                name for value in self.modules.values() for name in value
            ]
            mline = mline.title()
            comp_text = [s[offs:] for s in avb_modules if s.startswith(mline)]
        return comp_text

    def do_back(self, arg):
        """Go back from namespace or module"""

        if self.module:
            self.module = ""
        else:
            self.namespace = ""

    # -- information -----------------------------------------------------
    def do_info(self, arg):
        """Show information about the selected module"""

        if not self.module:
            logger.error("No module selected.")
            return
        module = self.modules[self.namespace][self.module]
        rows = [
            ["Namespace", self.namespace],
            ["Module", module.name],
            ["Risk", module.risk],
            ["Target OS", module.target_os],
            ["Requires root/admin", "yes" if module.require_superuser else "no"],
            ["Requires restart", "yes" if module.require_restart else "no"],
            ["CIS controls", ", ".join(module.cis) or "-"],
            ["NIST 800-53", ", ".join(module.nist) or "-"],
            ["Shell", "yes" if module.shell else "no"],
            ["Revert strategy", module.revert_strategy],
            ["Reversible", "yes" if module.revertible else "NO"],
            ["Description", module.desc],
            ["Check command", module.check_command],
            ["Apply command", module.command],
            ["Revert command", module.revert_command or "(restore backups)"],
        ]
        if module.files:
            rows.append(["Files backed up", "\n".join(module.files)])
        if module.irreversible:
            rows.append(["Irreversible", module.irreversible_reason])
        if module.notes:
            rows.append(["Notes", module.notes])
        print()
        print(render_table(["Property", "Value"], rows, max_col_width=72))
        print()

    def do_search(self, arg):
        """Search for modules"""

        if not arg:
            self.do_list(None)
            return
        rows = []
        for namespace, definitions in self.modules.items():
            for name, module in definitions.items():
                haystack = f"{namespace}/{name} {module.desc} {' '.join(module.tags)}"
                if arg.lower() in haystack.lower():
                    rows.append(
                        [
                            f"{namespace}/{name}",
                            module.risk,
                            "yes" if module.revertible else "NO",
                            module.desc,
                        ]
                    )
        if rows:
            print(render_table(["Module", "Risk", "Revert", "Description"], rows))
        else:
            logger.error(f'Nothing found for "{arg}".')

    def do_list(self, arg):
        """List available hardening modules"""

        rows = []
        namespaces = [self.namespace] if self.namespace else sorted(self.modules)
        for namespace in namespaces:
            for name, module in self.modules[namespace].items():
                rows.append(
                    [
                        f"{namespace}/{name}",
                        module.risk,
                        "yes" if module.revertible else "NO",
                        module.desc,
                    ]
                )
        print(render_table(["Module", "Risk", "Revert", "Description"], rows))

    # -- module authoring ------------------------------------------------
    @staticmethod
    def _namespaces(data):
        return [
            namespace
            for namespace in data
            if namespace not in ("presets", "schema_version", "metadata")
        ]

    def _choose_namespace(self, data, allow_new=True):
        choices = self._namespaces(data)
        if allow_new:
            choices = choices + ["+ new namespace"]
        choice = prompts.select("Namespace:", choices, default=0)
        if choice == "+ new namespace":
            def validate(value):
                import re
                if not re.match(r"^[a-z][a-z0-9_]{1,32}$", value):
                    return "Use lower case letters, digits and underscores (2-33 chars)."
                if value in data:
                    return "That namespace already exists."
                return None
            return prompts.text("New namespace", validate=validate)
        return choice

    def _choose_module(self, data, namespace):
        names = [module["name"] for module in data[namespace]]
        if not names:
            raise prompts.PromptError(f"namespace {namespace!r} has no modules")
        return prompts.select("Module:", names, default=0)

    def _prompt_command(self, label, required=True, default=""):
        return prompts.text(
            label,
            default=default,
            allow_empty=not required,
            validate=lambda value: None if value.strip() else f"{label} is required",
        )

    def do_manage(self, arg):
        """Add, edit or remove a module"""

        try:
            data = helpers.get_mod_json()
            option = prompts.select(
                "What do you want to do?",
                ["Add module", "Edit module", "Remove module"],
                default=0,
            )
            if option == "Add module":
                self._add_module(data)
            elif option == "Edit module":
                self._edit_module(data)
            else:
                self._remove_module(data)
        except prompts.PromptError as exc:
            logger.info(f"Module management cancelled: {exc}")
            return
        except Exception as exc:  # validation errors and I/O problems
            logger.error(f"Module management failed: {exc}")
            return
        self.modules = get_modules()
        self.namespace = ""
        self.module = ""

    def _add_module(self, data):
        namespace = self._choose_namespace(data)

        def validate_name(value):
            if not NAME_RE.match(value):
                return "Use letters, digits and underscores, starting with a letter."
            if any(
                module["name"].lower() == value.lower()
                for module in data.get(namespace, [])
            ):
                return "A module with that name already exists in this namespace."
            return None

        name = prompts.text("Module name", validate=validate_name)
        desc = prompts.text("Description")
        command = self._prompt_command("Apply command")
        check = self._prompt_command("Audit command (exit 0 = compliant)")
        shell = prompts.confirm(
            "Does the command need shell features (pipes, redirects, &&)?", default=False
        )
        irreversible = prompts.confirm(
            "Is this change genuinely impossible to revert?", default=False
        )
        revert = ""
        reason = ""
        if irreversible:
            reason = prompts.text("Why is it irreversible?")
        else:
            revert = self._prompt_command("Revert command")
        files = []
        if prompts.confirm("Does it modify files that should be backed up?", default=False):
            files = _split_list(
                prompts.text("Absolute paths (comma separated, globs allowed)", allow_empty=True)
            )

        module = {
            "name": name,
            "desc": desc,
            "command": command,
            "check": check,
            "revert": revert,
            "files": files,
            "shell": shell,
            "require_superuser": prompts.confirm(
                "Does it require root/administrator privileges?", default=True
            ),
            "require_restart": prompts.confirm(
                "Does it require a restart?", default=False
            ),
            "risk": prompts.select(
                "Risk level:", ["low", "medium", "high", "critical"], default=1
            ),
            "target_os": helpers.target_os_name(),
            "irreversible": irreversible,
            "irreversible_reason": reason,
        }
        data.setdefault(namespace, []).append(module)
        helpers.save_mod_json(data)
        logger.info(f"Module {namespace}/{name} added and validated.")

    def _edit_module(self, data):
        namespace = self._choose_namespace(data, allow_new=False)
        module_name = self._choose_module(data, namespace)
        module = next(m for m in data[namespace] if m["name"] == module_name)
        field = prompts.select("Field to edit:", MODULE_FIELDS, default=0)
        current = module.get(field, "")
        if field in ("shell", "require_superuser", "require_restart"):
            value = prompts.confirm(f"New value for {field}", default=bool(current))
        elif field in ("files", "cis", "nist"):
            value = _split_list(
                prompts.text(
                    f"New value for {field} (comma separated)",
                    default=", ".join(current) if isinstance(current, list) else str(current),
                    allow_empty=True,
                )
            )
        else:
            value = self._prompt_command(f"New value for {field}", default=str(current))
        module[field] = value
        helpers.save_mod_json(data)
        logger.info(f"Module {namespace}/{module_name} updated and validated.")

    def _remove_module(self, data):
        namespace = self._choose_namespace(data, allow_new=False)
        module_name = self._choose_module(data, namespace)
        if not prompts.confirm(f"Remove {namespace}/{module_name}?", default=False):
            logger.info("Removal cancelled.")
            return
        data[namespace] = [m for m in data[namespace] if m["name"] != module_name]
        if not data[namespace]:
            del data[namespace]
        helpers.save_mod_json(data)
        logger.info(f"Module {namespace}/{module_name} removed.")

    # -- hardening -------------------------------------------------------
    def _options(self):
        return {
            "dry_run": self.options.get("dry_run", False),
            "force": self.options.get("force", False),
            "allow_unrevertible": self.options.get("allow_unrevertible", False),
            "allow_irreversible": self.options.get("allow_irreversible", False),
        }

    def do_check(self, arg):
        """Audit the selected module (or a target) without changing anything"""

        if not arg and not self.module:
            logger.error("Select a module or pass a target (namespace or namespace/Module).")
            return
        try:
            modules = [self.modules[self.namespace][self.module]] if not arg else \
                helpers.resolve_targets(arg, self.modules)
        except KeyError as exc:
            logger.error(str(exc))
            return
        rows = []
        failed = 0
        for module in modules:
            result = module.check()
            failed += 0 if result.ok else 1
            rows.append(
                [
                    module.qualified_name,
                    "compliant" if result.ok else "drift",
                    result.summary(120),
                ]
            )
        print(render_table(["Module", "State", "Evidence"], rows))
        logger.info(
            f"{len(modules) - failed}/{len(modules)} module(s) compliant."
        )

    def do_harden(self, arg):
        """Apply the selected hardening module"""

        if not (self.module and self.namespace):
            logger.error("Select a module first (use [namespace/Module]).")
            return
        module = self.modules[self.namespace][self.module]
        options = self._options()
        if module.require_restart:
            logger.info(
                f"{self.module} requires a restart of the OS or service for the "
                "changes to apply."
            )
        if not options["dry_run"] and not self.options.get("yes"):
            try:
                if not prompts.confirm(f"Apply {module.qualified_name}?", default=False):
                    logger.info("Hardening cancelled.")
                    return
            except prompts.PromptError as exc:
                logger.error(f"Cannot ask for confirmation: {exc}")
                return
        try:
            outcome = module.apply(journal=self.journal, **options)
        except PermissionError as exc:
            logger.error(str(exc))
            return
        except Exception as exc:
            logger.error(f"Failed to execute hardening command: {exc}")
            return

        if outcome.already_compliant:
            logger.info(f"{module.qualified_name} is already compliant.")
            return
        for message in outcome.messages:
            logger.info(message)
        if outcome.ok:
            logger.info("Hardening command executed successfully.")
            if outcome.journaled:
                logger.info(f"Run id: {outcome.run_id} (undo: revert {outcome.run_id})")
            if outcome.verified is True:
                logger.info("Audit command confirms the module is now compliant.")
            elif outcome.verified is False:
                logger.warn(
                    "The audit command still reports drift after hardening; "
                    "inspect the output or revert the change."
                )
            if outcome.result.stdout.strip():
                print(outcome.result.stdout.rstrip())
        else:
            logger.error(f"Hardening failed: {outcome.result.summary(400)}")

    def do_revert(self, arg):
        """Revert applied changes: 'revert', 'revert last', 'revert all', a run id or a module"""

        spec = (arg or "").strip()
        if not spec:
            pending = self.journal.pending()
            if not pending:
                logger.info("Nothing to revert: the journal has no pending runs.")
                return
            rows = [
                [record.run_id, record.module, record.summary_row()[1]]
                for record in pending
            ]
            print(render_table(["Run id", "Module", "Applied at"], rows))
            logger.info("Use 'revert last', 'revert all' or 'revert <run id>'.")
            return

        runs = resolve_runs(self.journal, spec)
        if not runs:
            logger.error(f"Nothing to revert for '{spec}'.")
            return
        if len(runs) > 1 and not self.options.get("yes"):
            try:
                if not prompts.confirm(f"Revert {len(runs)} run(s)?", default=False):
                    logger.info("Revert cancelled.")
                    return
            except prompts.PromptError as exc:
                logger.error(f"Cannot ask for confirmation: {exc}")
                return

        failures = 0
        for record in runs:
            outcome = revert_record(
                record, journal=self.journal, dry_run=self.options.get("dry_run", False)
            )
            if outcome.ok:
                logger.info(
                    f"Reverted {record.module} (run {record.run_id})."
                    + (" [dry-run]" if outcome.dry_run else "")
                )
            else:
                failures += 1
                logger.error(
                    f"Could not revert {record.module} (run {record.run_id}): "
                    f"{outcome.error or 'see restored paths'}"
                )
            for item in outcome.restored:
                print(f"\t{item['action']:<10} {item['path']}")
            for message in outcome.messages:
                logger.info(message)
        if failures:
            logger.error(f"{failures} run(s) could not be reverted.")

    def do_history(self, arg):
        """Show recent journal entries"""

        limit = 20
        if arg.strip().isdigit():
            limit = max(1, int(arg.strip()))
        records = self.journal.history(limit)
        if not records:
            logger.info(f"No journal entries yet ({self.journal.path}).")
            return
        rows = [record.summary_row() for record in records]
        print(render_table(["Run id", "When", "Module", "State"], rows))
        ok, problems = self.journal.verify_chain()
        if ok:
            logger.info(f"Journal integrity verified ({self.journal.path}).")
        else:
            for problem in problems:
                logger.error(f"Journal integrity: {problem}")

    def do_audit(self, arg):
        """Audit every module in the current namespace (or a target)"""

        target = arg.strip() or (self.namespace if self.namespace else "all")
        try:
            modules = helpers.resolve_targets(target, self.modules)
        except KeyError as exc:
            logger.error(str(exc))
            return
        rows = []
        drift = 0
        for module in modules:
            result = module.check()
            if not result.ok:
                drift += 1
            rows.append(
                [
                    module.qualified_name,
                    "compliant" if result.ok else "drift",
                    module.risk,
                    result.summary(100),
                ]
            )
        print(render_table(["Module", "State", "Risk", "Evidence"], rows))
        logger.info(
            f"{len(modules) - drift}/{len(modules)} module(s) compliant, {drift} drift."
        )

    # -- presets ---------------------------------------------------------
    def do_preset(self, arg):
        """Execute the hardening modules of a preset"""

        import textwrap

        presets = get_presets()
        if not arg:
            if not presets:
                logger.warn(f"No presets found in {helpers.paths.modules_file()}")
                return
            rows = [
                [item["name"], item.get("risk", "-"), "\n".join(item["modules"])]
                for item in presets
            ]
            print(render_table(["Preset", "Risk", "Modules"], rows))
            if presets[0].get("desc"):
                print(textwrap.fill(presets[0]["desc"], 78))
            return

        preset = helpers.get_preset(arg)
        if preset is None:
            logger.error(f"No preset named '{arg}' for this OS.")
            return
        modules = []
        for member in preset["modules"]:
            try:
                modules.extend(helpers.resolve_targets(member, self.modules))
            except KeyError as exc:
                logger.error(f"Preset {preset['name']}: {exc}")
                return

        logger.info(
            f"Preset {preset['name']} contains {len(modules)} module(s); "
            f"risk: {preset.get('risk', 'unspecified')}."
        )
        failures = 0
        for module in modules:
            if not self.options.get("yes") and not self.options.get("dry_run"):
                try:
                    if not prompts.confirm(
                        f"Apply {module.qualified_name}?", default=False
                    ):
                        logger.info(f"Skipped {module.qualified_name}.")
                        continue
                except prompts.PromptError as exc:
                    logger.error(f"Cannot ask for confirmation: {exc}")
                    return
            try:
                outcome = module.apply(journal=self.journal, **self._options())
            except PermissionError as exc:
                failures += 1
                logger.error(str(exc))
                continue
            if outcome.already_compliant:
                logger.info(f"{module.qualified_name} already compliant.")
            elif outcome.ok:
                logger.info(
                    f"Applied {module.qualified_name}"
                    + (f" (run {outcome.run_id})" if outcome.journaled else "")
                )
            else:
                failures += 1
                logger.error(
                    f"{module.qualified_name} failed: {outcome.result.summary(200)}"
                )
        if failures:
            logger.error(f"Preset {preset['name']} finished with {failures} failure(s).")
        else:
            logger.info(f"Preset {preset['name']} finished successfully.")

    # -- web -------------------------------------------------------------
    def do_web(self, arg):
        """Start the grapheneX web server"""

        from graphenex.core.web import run_server

        helpers.create_env_file()
        run_server({"host_port": arg} if arg else None, False)

    # -- shell housekeeping ----------------------------------------------
    def do_EOF(self, arg):
        """EOF exit"""

        print()
        self.do_exit(arg)
        return True

    @staticmethod
    def do_exit(arg):
        """Exit interactive shell"""

        exit_msgs = [
            "Bye!",
            "Hope to see you soon!",
            "Take care!",
            "I am not going to miss you!",
            "Gonna miss you!",
            "Thank God, you're leaving. What a relief!",
            "Fare thee well!",
            "Farewell, boss.",
            "Daha karpuz kesecektik.",
            "Bon voyage!",
            "Regards.",
            "Exiting...",
        ]
        logger.info(random.choice(exit_msgs))
        return True

    @staticmethod
    def do_clear(arg):
        """Clear the terminal"""

        import os

        os.system("cls" if check_os() else "clear")

    @staticmethod
    def default(line):
        """Default command"""

        logger.error("Command not found. Type 'help' to list commands.")
