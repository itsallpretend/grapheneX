"""Help for the interactive shell."""

from __future__ import annotations

from graphenex.core.cli.table import render_table
from graphenex.core.utils.logcl import GraphenexLogger

logger = GraphenexLogger(__name__)


class Help:
    """Help class that will contain help methods for specific commands"""

    def do_help(self, arg):
        """List available commands with 'help' or show detailed help with 'help <cmd>'"""

        if arg:
            try:
                func = getattr(self, f"do_{arg}")
            except AttributeError:
                logger.error(f'Cannot find help method for "{arg}".')
                return
            helper = getattr(self, f"help_{arg}", None)
            if helper:
                helper()
            else:
                print(f"\n\tSyntax: {func.__name__[3:]}\n\t{func.__doc__ or 'No description'}\n")
            return

        rows = []
        for name in self.get_names():
            if name.startswith("do_") and name != "do_EOF":
                command = getattr(self, name)
                rows.append([command.__name__[3:], command.__doc__ or "No description"])
        print(render_table(["Command", "Description"], rows))

    @staticmethod
    def message(syntax, content):
        """Print the commands help message with its syntax"""

        print(f"\n\tSyntax: {syntax}\n\t{content}\n")

    def help_switch(self):
        self.message("switch [namespace]", "Switch between namespaces")

    def help_search(self):
        self.message("search [query]", "Search module names, descriptions and tags")

    def help_use(self):
        self.message("use [namespace/Module]", "Select a hardening module")

    def help_check(self):
        self.message(
            "check [target]",
            "Run the audit command of the selected module or target "
            "(exit code 0 means compliant). Use 'audit' for a whole namespace.",
        )

    def help_audit(self):
        self.message(
            "audit [target]",
            "Audit every module of the current namespace, a namespace or 'all'.",
        )

    def help_harden(self):
        self.message(
            "harden",
            "Apply the selected module. Backups and a journal entry are created "
            "automatically so the change can be reverted.",
        )

    def help_revert(self):
        self.message(
            "revert [last|all|RUN_ID|MODULE]",
            "Undo applied changes. With no argument the pending runs are listed.",
        )

    def help_history(self):
        self.message("history [N]", "Show the last N journal entries (default 20)")

    def help_manage(self):
        self.message(
            "manage",
            "Add, edit or remove modules. Every change is validated against the "
            "module schema (apply, audit and revert commands are mandatory).",
        )

    def help_preset(self):
        self.message("preset [preset]", "Execute the hardening modules of a preset")

    def help_web(self):
        self.message("web [host:port]", "Start the web server")
