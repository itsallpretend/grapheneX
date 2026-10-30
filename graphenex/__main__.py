"""grapheneX command line entry point."""

from __future__ import annotations

import sys

from graphenex import __version__
from graphenex.core.cli import batch
from graphenex.core.utils.helpers import create_env_file, parse_cli_args, print_header
from graphenex.core.utils.logcl import GraphenexLogger, configure

logger = GraphenexLogger("Graphenex")


def main(argv=None):
    args = parse_cli_args(argv)
    if args["version"]:
        print(f"grapheneX v{__version__}")
        return 0

    if args["quiet"]:
        configure("ERROR")

    machine_output = bool(args["json"])
    if batch.is_batch(args):
        print_header(quiet=args["quiet"] or machine_output)
        try:
            return batch.run(args)
        except KeyboardInterrupt:
            print("Interrupted.", file=sys.stderr)
            return 130

    print_header(quiet=args["quiet"])

    if args["web"]:
        # Only the web interface needs a session secret.
        create_env_file(args["flask_secret_key"])
        from graphenex.core.web import run_server

        run_server(args)
        return 0

    if args["open"]:
        logger.warn("[--open] argument is unnecessary. Use it with [-w] or [--web].")

    from graphenex.core.cli.shell import start_cli

    start_cli(options=args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
