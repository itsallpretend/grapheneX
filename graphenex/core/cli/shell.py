"""Interactive shell entry point."""

from __future__ import annotations

from cmd import Cmd

from graphenex.core.cli.commands import ShellCommands
from graphenex.core.hrd.journal import Journal
from graphenex.core.utils.helpers import get_modules


class Shell(ShellCommands, Cmd):
    """Interactive Shell constructor class"""

    namespace = ""
    module = ""
    modules = {}
    options = {}

    def __init__(self, options=None, journal=None):
        super().__init__()
        self.options = dict(options or {})
        self.journal = journal or Journal()
        self.modules = get_modules()
        module_count = sum(len(modules) for modules in self.modules.values())
        pending = self.journal.pending()
        intro = (
            "Welcome to the grapheneX interactive shell. "
            'Type "help" or "?" to list commands.\n'
            f"{module_count} module(s) available"
        )
        if pending:
            intro += (
                f"; {len(pending)} change(s) can still be reverted "
                "('revert last')"
            )
        self.intro = intro

    @property
    def prompt(self):
        """Set prompt according to the current module and namespace"""

        prompt_str = ""
        if self.namespace:
            prompt_str = prompt_str + ":" + self.namespace
        if self.module:
            prompt_str = prompt_str + ":" + self.module
        return f"[gX{prompt_str}]> "


def start_cli(options=None):
    """Start the command line interface."""

    shell = Shell(options=options)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        shell.do_EOF(None)
