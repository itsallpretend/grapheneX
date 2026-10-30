"""Shared helpers: CLI arguments, module loading, privileges and secrets."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys

from graphenex.core.hrd import HardenMethod
from graphenex.core.hrd.schema import ModuleValidationError, validate_modules
from graphenex.core.utils import paths, privileges
from graphenex.core.utils.logcl import GraphenexLogger

logger = GraphenexLogger(__name__)

#: Kept for backwards compatibility with third-party code.
mod_json_file = paths.default_modules_file()

TARGET_ALL = "all"


def parse_cli_args(argv=None):
    """Command-line argument parser (also used by ``__main__``)."""

    parser = argparse.ArgumentParser(
        prog="grapheneX",
        description="grapheneX | Automated System Hardening Framework",
        epilog="Every hardening module ships with an audit (--check) and a "
        "revert (--revert) path. Use --dry-run to see what would happen.",
    )
    parser.add_argument("-v", "--version", action="store_true",
                        help="show version information and exit")
    parser.add_argument("-w", "--web", action="store_true",
                        help="start the grapheneX web server")
    parser.add_argument("host_port", metavar="host:port", type=str, nargs="?",
                        default=None,
                        help="host and port for the web interface "
                             "(default: 127.0.0.1:8080)")
    parser.add_argument("--open", action="store_true",
                        help="open the browser when the web server starts")
    parser.add_argument("--flask-secret-key", default=None,
                        help="secret key used to sign client-side sessions")

    batch = parser.add_argument_group("non-interactive (batch) mode")
    batch.add_argument("--list", action="store_true",
                       help="list every module available for this OS")
    batch.add_argument("--check", nargs="?", const=TARGET_ALL, metavar="TARGET",
                       help="audit modules; TARGET is 'all', a namespace or "
                            "'namespace/Module_Name' (default: all)")
    batch.add_argument("--apply", nargs="?", const=TARGET_ALL, metavar="TARGET",
                       help="apply modules (same TARGET syntax as --check)")
    batch.add_argument("--revert", nargs="?", const="last", metavar="RUN",
                       help="revert a run: 'last', 'all', a run id or a target")
    batch.add_argument("--history", nargs="?", const=20, type=int, metavar="N",
                       help="show the last N journal entries (default: 20)")
    batch.add_argument("--validate", action="store_true",
                       help="validate modules.json and exit")

    options = parser.add_argument_group("behaviour")
    options.add_argument("--json", action="store_true",
                         help="machine readable JSON on stdout")
    options.add_argument("--dry-run", action="store_true",
                         help="show what would change without changing anything")
    options.add_argument("--force", action="store_true",
                         help="apply even if the module already reports compliant")
    options.add_argument("--yes", "-y", action="store_true",
                         help="answer every confirmation with yes")
    options.add_argument("--no-color", action="store_true",
                         help="disable coloured output")
    options.add_argument("--quiet", "-q", action="store_true",
                         help="only print warnings and errors")
    options.add_argument("--state-dir", default=None,
                         help="directory for the journal and backups")
    options.add_argument("--modules", default=None,
                         help="path to an alternative modules.json")
    options.add_argument("--allow-unrevertible", action="store_true",
                         help="allow legacy modules without a revert definition")
    options.add_argument("--allow-irreversible", action="store_true",
                         help="allow modules explicitly marked irreversible")

    args = vars(parser.parse_args(argv))
    if args["no_color"]:
        os.environ["NO_COLOR"] = "1"
    if args["yes"]:
        os.environ["GRAPHENEX_ASSUME_YES"] = "1"
    if args["state_dir"]:
        os.environ["GRAPHENEX_STATE_DIR"] = os.path.abspath(args["state_dir"])
    if args["modules"]:
        os.environ["GRAPHENEX_MODULES"] = os.path.abspath(args["modules"])
    return args


def print_header(quiet=False):
    """Show the project banner (skipped in quiet/JSON mode)."""

    if quiet:
        return
    banner = """
                 +ho:`
           `:ohh. /dddy/.
        ./ydddddd/ -hddddho:          | grapheneX |
    `:ohdddddddddds``sddddds- :.      ~ Automated System Hardening Framework
    +ddddddddddddddh. /dds- /hdd      + Created for Linux & Windows.
    +dddddddddddddddd/ .. /hdddd      > https://github.com/grapheneX
    +ddddddddddddddddo``/hdddddd      - Copyright (C) 2019-2026
    +ddddddddddddddo.`+ddddddddd
    `-/+oyhddddd+``+dddddddddddd
    :o+/-.` `-` .syddddddddddddd
    +dddddddyso+:-. `.-/+oyhdddd
     -+yddddddddddddhyso/:-` `-`
        `/sddddddddddddddy+-
            -+hddddddds:`
               `/sy+-
    """
    print(banner)
    logger.info("grapheneX started.")
    check_privileges()


def check_os():
    """
    Returns operating system information.
    [1] -> Windows
    [0] -> Linux (else)
    """

    return 1 if os.name == "nt" else 0


def target_os_name() -> str:
    return "win" if check_os() else "linux"


def check_privileges():
    """Warn when the current user cannot apply privileged modules."""

    if not privileges.is_elevated():
        logger.warn(
            "Some modules require administrative/root privileges. "
            + privileges.elevation_hint()
        )
    return privileges.is_elevated()


def get_mod_json():
    """Read the active modules file and return the parsed JSON."""

    path = paths.modules_file()
    try:
        with open(path, "r", encoding="utf-8") as json_file:
            return json.load(json_file)
    except FileNotFoundError:
        logger.error(f"{path} not found! Exiting grapheneX.")
        sys.exit(1)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error(f"Cannot read {path}: {exc}")
        sys.exit(1)


def save_mod_json(data):
    """Validate and atomically write the modules file."""

    report = validate_modules(data, source=str(paths.modules_file()))
    if not report.ok:
        raise ModuleValidationError(report.errors)
    body = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
    paths.atomic_write(paths.modules_file(), body, mode=0o644)
    return report


def get_validation_report():
    """Return the schema validation report for the active modules file."""

    return validate_modules(get_mod_json(), source=str(paths.modules_file()))


def log_validation_issues(report):
    """Print validation problems in a compact, actionable way."""

    for issue in report.errors:
        logger.error(f"module validation: {issue}")
    for issue in report.warnings:
        logger.warn(f"module validation: {issue}")


def get_modules(os_name=None, report=None):
    """Return validated hardening modules for the current OS.

    Structure: ``{namespace: {module_name: HardenMethod}}``. Modules that fail
    validation are logged and skipped (fail closed).
    """

    os_name = os_name or target_os_name()
    report = report or get_validation_report()
    log_validation_issues(report)

    modules = {}
    for namespace, definitions in report.modules.items():
        selected = {
            name: HardenMethod(namespace=namespace, **definition)
            for name, definition in definitions.items()
            if definition["target_os"] == os_name
        }
        if selected:
            modules[namespace] = selected
    return modules


def get_forbidden_namespaces(os_name=None):
    """Return the namespaces that do not contain modules for this OS."""

    os_name = os_name or target_os_name()
    json_data = get_mod_json()
    namespaces = []
    for namespace, modlist in json_data.items():
        if namespace in ("presets", "schema_version", "metadata"):
            continue
        targets = {module.get("target_os") for module in modlist if isinstance(module, dict)}
        if os_name not in targets:
            namespaces.append(namespace)
    namespaces.append("presets")
    return namespaces


def get_presets(os_name=None):
    """Return the presets that target this OS."""

    os_name = os_name or target_os_name()
    presets = get_mod_json().get("presets") or []
    return [preset for preset in presets if preset.get("target_os") == os_name]


def get_preset(name, os_name=None):
    """Find a preset by name (case insensitive)."""

    for preset in get_presets(os_name):
        if preset["name"].lower() == str(name).lower():
            return preset
    return None


def resolve_targets(target, modules=None):
    """Expand a CLI target into a list of :class:`HardenMethod` objects.

    ``target`` may be ``all``, a namespace name or ``namespace/Module_Name``.
    """

    modules = modules if modules is not None else get_modules()
    if not target or target == TARGET_ALL:
        return [mod for namespace in modules.values() for mod in namespace.values()]

    target_lower = str(target).lower()
    if "/" in target_lower:
        namespace, _, name = target_lower.partition("/")
        namespace_mods = modules.get(namespace, {})
        for module_name, module in namespace_mods.items():
            if module_name.lower() == name:
                return [module]
        raise KeyError(f"unknown module {target!r}")

    if target_lower in modules:
        return list(modules[target_lower].values())

    matches = [
        module
        for namespace in modules.values()
        for module_name, module in namespace.items()
        if module_name.lower() == target_lower
    ]
    if len(matches) == 1:
        return matches
    if len(matches) > 1:
        raise KeyError(f"ambiguous module {target!r}: use namespace/Module_Name")
    raise KeyError(f"unknown namespace or module {target!r}")


def is_valid_port(port):
    """Verify the port number."""

    return isinstance(port, int) and 1 <= port <= 65535


def is_valid_address(address):
    """Verify a listen address (IP address or resolvable hostname)."""

    try:
        socket.getaddrinfo(address, None)
        return True
    except (socket.gaierror, UnicodeError, TypeError):
        return False


def is_loopback(address):
    """Return ``True`` for loopback listen addresses."""

    return address in ("localhost", "127.0.0.1", "::1")


def create_env_file(cli_secret_key=None):
    """Create the config file holding the Flask secret key (mode 0600)."""

    path = paths.env_file()
    existing = paths.read_env_file(path)
    if cli_secret_key:
        paths.write_env_value(path, "FLASK_SECRET_KEY", cli_secret_key)
        logger.info(f"Flask secret key stored in {path}")
        return cli_secret_key
    if not existing.get("FLASK_SECRET_KEY"):
        paths.write_env_value(path, "FLASK_SECRET_KEY", secrets.token_hex(32))
        logger.info(f"Generated a new Flask secret key in {path}")
    return paths.read_env_file(path).get("FLASK_SECRET_KEY")


def get_flask_secret_key():
    """Load the Flask secret key from the config file."""

    return paths.read_env_file(paths.env_file()).get("FLASK_SECRET_KEY")
