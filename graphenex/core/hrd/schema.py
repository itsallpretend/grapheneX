"""
Module schema for grapheneX.

``modules.json`` entries are executable code. Historically any dictionary with
a ``command`` key was accepted, which meant a typo, a stale module or a
malicious edit could not be told apart from a valid module. Schema version 2
turns the file into a validated contract:

* ``command``  -- apply the hardening change.
* ``check``    -- audit the current state, exit ``0`` means "compliant".
* ``revert``   -- undo the change. Mandatory unless the module is explicitly
                  declared ``irreversible`` (which then needs a reason and a
                  conscious opt-in to execute).

Everything else is metadata used for reporting, compliance mapping and risk
scoring. Validation never raises on the first problem: it collects every issue
so that ``grapheneX --validate`` can print a complete report.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass, field
from typing import Iterable

SCHEMA_VERSION = 2

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}$")
NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9_]{1,32}$")
CIS_RE = re.compile(r"^[0-9]+(\.[0-9]+){0,3}$")
NIST_RE = re.compile(r"^[A-Z]{2}-[0-9]+(\.[0-9]+)?$")
RISK_LEVELS = ("low", "medium", "high", "critical")
SHELL_MARKERS = ("|", ">", "<", "&&", ";", "`", "$(")
TARGET_OS = ("linux", "win")
RESERVED_KEYS = ("presets", "schema_version", "metadata")

REQUIRED_FIELDS = ("name", "desc", "command", "check", "target_os")
OPTIONAL_FIELDS = (
    "revert",
    "files",
    "shell",
    "timeout",
    "require_superuser",
    "require_restart",
    "cis",
    "nist",
    "risk",
    "tags",
    "notes",
    "probe",
    "irreversible",
    "irreversible_reason",
    "requires",
    "idempotent",
)
KNOWN_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS

MAX_DESC_LENGTH = 600
MAX_COMMAND_LENGTH = 8192
DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 3600
MIN_TIMEOUT = 1


@dataclass
class ModuleIssue:
    """A single validation problem found in a module definition."""

    module: str
    field: str
    message: str
    severity: str = "error"

    def __str__(self) -> str:
        return f"[{self.severity}] {self.module}: {self.field}: {self.message}"

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "field": self.field,
            "message": self.message,
            "severity": self.severity,
        }


class ModuleValidationError(ValueError):
    """Raised when a module definition does not satisfy the schema."""

    def __init__(self, issues: Iterable[ModuleIssue]):
        self.issues = list(issues)
        super().__init__("; ".join(str(issue) for issue in self.issues))


@dataclass
class ValidationReport:
    """Result of validating a whole ``modules.json`` file."""

    modules: dict = field(default_factory=dict)
    presets: list = field(default_factory=list)
    issues: list = field(default_factory=list)

    @property
    def errors(self) -> list:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "module_count": sum(len(mods) for mods in self.modules.values()),
            "namespace_count": len(self.modules),
            "preset_count": len(self.presets),
            "errors": [issue.to_dict() for issue in self.errors],
            "warnings": [issue.to_dict() for issue in self.warnings],
        }


def _as_bool(value, default=False):
    """Accept the legacy ``"True"``/``"False"`` strings as well as booleans."""

    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1", "on"):
            return True
        if lowered in ("false", "no", "0", "off"):
            return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ValueError(f"expected a boolean, got {value!r}")


def _as_str_list(value, field_name):
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be a list of strings")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} must only contain strings")
        item = item.strip()
        if item:
            result.append(item)
    return result



def _validate_command(command: str, field_name: str, shell: bool, issues: list, label: str) -> None:
    from graphenex.core.hrd.exec import build_argv

    if not isinstance(command, str) or not command.strip():
        issues.append(ModuleIssue(label, field_name, "must be a non-empty string"))
        return
    if len(command) > MAX_COMMAND_LENGTH:
        issues.append(
            ModuleIssue(label, field_name, f"is longer than {MAX_COMMAND_LENGTH} characters")
        )
    try:
        build_argv(command, shell=shell)
    except ValueError as exc:
        issues.append(ModuleIssue(label, field_name, str(exc)))
        return
    if not shell and any(marker in command for marker in SHELL_MARKERS):
        issues.append(
            ModuleIssue(
                label,
                field_name,
                "contains shell metacharacters but the module does not set "
                "'shell': true, so they will be passed literally",
                severity="warning",
            )
        )


def _validate_paths(paths: list, issues: list, label: str) -> None:
    for path in paths:
        if not path.startswith("/"):
            issues.append(
                ModuleIssue(label, "files", f"{path!r} must be an absolute path")
            )
            continue
        if ".." in pathlib.PurePosixPath(path).parts:
            issues.append(ModuleIssue(label, "files", f"{path!r} must not contain '..'"))
        if path.rstrip("/") in ("", "/etc", "/usr", "/var", "/boot", "/home"):
            issues.append(
                ModuleIssue(label, "files", f"{path!r} is too broad to snapshot safely")
            )


def normalize_module(raw: dict) -> dict:
    """
    Validate and normalize a single module definition.

    Raises :class:`ModuleValidationError` with every issue that was found.
    The returned dictionary contains all optional fields with defaults filled
    in so that the rest of the framework never has to use ``.get()``.
    """

    issues: list[ModuleIssue] = []
    if not isinstance(raw, dict):
        raise ModuleValidationError(
            [ModuleIssue("<unknown>", "<module>", "must be a JSON object")]
        )

    label = raw.get("name") if isinstance(raw.get("name"), str) else "<unnamed>"
    name = raw.get("name", "")
    if not isinstance(name, str) or not NAME_RE.match(name):
        issues.append(
            ModuleIssue(label, "name", "must match ^[A-Za-z][A-Za-z0-9_]{2,63}$")
        )

    desc = raw.get("desc", "")
    if not isinstance(desc, str) or not desc.strip():
        issues.append(ModuleIssue(label, "desc", "must be a non-empty string"))
    elif len(desc) > MAX_DESC_LENGTH:
        issues.append(
            ModuleIssue(label, "desc", f"must be at most {MAX_DESC_LENGTH} characters")
        )

    target_os = raw.get("target_os")
    if target_os not in TARGET_OS:
        issues.append(
            ModuleIssue(label, "target_os", f"must be one of {', '.join(TARGET_OS)}")
        )

    try:
        shell = _as_bool(raw.get("shell"), False)
    except ValueError as exc:
        issues.append(ModuleIssue(label, "shell", str(exc)))
        shell = False

    try:
        is_irreversible = _as_bool(raw.get("irreversible"), False)
    except ValueError as exc:
        issues.append(ModuleIssue(label, "irreversible", str(exc)))
        is_irreversible = False

    command = raw.get("command", "")
    check = raw.get("check", "")
    _validate_command(command, "command", shell, issues, label)
    _validate_command(check, "check", shell, issues, label)

    has_files = bool(raw.get("files"))
    revert = raw.get("revert") or ""
    if revert:
        _validate_command(revert, "revert", shell, issues, label)
    elif not is_irreversible and not has_files:
        issues.append(
            ModuleIssue(
                label,
                "revert",
                "is required unless the module snapshots 'files' for "
                "restore or is declared irreversible with a reason",
            )
        )

    if is_irreversible:
        reason = raw.get("irreversible_reason", "")
        if not isinstance(reason, str) or not reason.strip():
            issues.append(
                ModuleIssue(
                    label, "irreversible_reason", "is required for irreversible modules"
                )
            )
        issues.append(
            ModuleIssue(
                label,
                "revert",
                "module is irreversible and cannot be rolled back",
                severity="warning",
            )
        )

    try:
        files = _as_str_list(raw.get("files"), "files")
    except ValueError as exc:
        issues.append(ModuleIssue(label, "files", str(exc)))
        files = []
    _validate_paths(files, issues, label)

    try:
        cis = _as_str_list(raw.get("cis"), "cis")
    except ValueError as exc:
        issues.append(ModuleIssue(label, "cis", str(exc)))
        cis = []
    for control in cis:
        if not CIS_RE.match(control):
            issues.append(
                ModuleIssue(label, "cis", f"{control!r} is not a CIS control number")
            )

    try:
        nist = _as_str_list(raw.get("nist"), "nist")
    except ValueError as exc:
        issues.append(ModuleIssue(label, "nist", str(exc)))
        nist = []
    for control in nist:
        if not NIST_RE.match(control):
            issues.append(
                ModuleIssue(label, "nist", f"{control!r} is not an 800-53 control")
            )

    try:
        tags = _as_str_list(raw.get("tags"), "tags")
    except ValueError as exc:
        issues.append(ModuleIssue(label, "tags", str(exc)))
        tags = []

    risk = raw.get("risk", "medium")
    if risk not in RISK_LEVELS:
        issues.append(
            ModuleIssue(label, "risk", f"must be one of {', '.join(RISK_LEVELS)}")
        )
        risk = "medium"

    timeout = raw.get("timeout", DEFAULT_TIMEOUT)
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        issues.append(
            ModuleIssue(label, "timeout", "must be an integer number of seconds")
        )
        timeout = DEFAULT_TIMEOUT
    elif not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        issues.append(
            ModuleIssue(
                label,
                "timeout",
                f"must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds",
            )
        )
        timeout = DEFAULT_TIMEOUT

    booleans = {}
    for flag in ("require_superuser", "require_restart", "idempotent"):
        try:
            booleans[flag] = _as_bool(raw.get(flag), False)
        except ValueError as exc:
            issues.append(ModuleIssue(label, flag, str(exc)))
            booleans[flag] = False

    probe = raw.get("probe") or ""
    if probe:
        _validate_command(probe, "probe", shell, issues, label)

    for unknown in sorted(set(raw) - set(KNOWN_FIELDS)):
        issues.append(
            ModuleIssue(
                label,
                unknown,
                "unknown field (typo? it will be ignored)",
                severity="warning",
            )
        )

    if any(issue.severity == "error" for issue in issues):
        raise ModuleValidationError(issues)

    if revert and files:
        revert_strategy = "command+files"
    elif revert:
        revert_strategy = "command"
    elif files:
        revert_strategy = "files"
    else:
        revert_strategy = "none"

    return {
        "name": name,
        "desc": desc.strip(),
        "command": command.strip(),
        "check": check.strip(),
        "revert": revert.strip(),
        "files": files,
        "shell": shell,
        "timeout": timeout,
        "require_superuser": booleans["require_superuser"],
        "require_restart": booleans["require_restart"],
        "idempotent": booleans["idempotent"],
        "target_os": target_os,
        "cis": cis,
        "nist": nist,
        "tags": tags,
        "risk": risk,
        "notes": (raw.get("notes") or "").strip(),
        "probe": probe.strip(),
        "irreversible": is_irreversible,
        "irreversible_reason": (raw.get("irreversible_reason") or "").strip(),
        "requires": _as_str_list(raw.get("requires"), "requires"),
        "schema_version": SCHEMA_VERSION,
        "issues": issues,
    }





def validate_modules_file(path) -> ValidationReport:
    """
    Load and validate a ``modules.json`` file.

    Invalid modules are reported and *excluded* from the returned report
    (fail closed: a module that cannot be validated is never executed).
    """

    import json

    report = ValidationReport()
    path = pathlib.Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        report.issues.append(ModuleIssue("<file>", "<file>", f"{path} not found"))
        return report
    except (OSError, json.JSONDecodeError) as exc:
        report.issues.append(
            ModuleIssue("<file>", "<file>", f"cannot be parsed: {exc}")
        )
        return report

    return validate_modules(data, source=str(path))


def validate_modules(data: dict, source: str = "<memory>") -> ValidationReport:
    """Validate already-parsed ``modules.json`` content."""

    report = ValidationReport()
    if not isinstance(data, dict):
        report.issues.append(
            ModuleIssue("<file>", "<file>", f"{source} must contain a JSON object")
        )
        return report

    for namespace, modules in data.items():
        if namespace in RESERVED_KEYS:
            continue
        if not NAMESPACE_RE.match(namespace):
            report.issues.append(
                ModuleIssue(namespace, "namespace", "must match ^[a-z][a-z0-9_]{1,32}$")
            )
            continue
        if not isinstance(modules, list):
            report.issues.append(
                ModuleIssue(namespace, "namespace", "must be a list of modules")
            )
            continue

        seen: set[str] = set()
        report.modules[namespace] = {}
        for raw in modules:
            try:
                module = normalize_module(raw)
            except ModuleValidationError as exc:
                report.issues.extend(exc.issues)
                continue
            key = module["name"].lower()
            if key in seen:
                report.issues.append(
                    ModuleIssue(
                        module["name"],
                        "name",
                        f"duplicate module name in namespace {namespace!r}",
                    )
                )
                continue
            seen.add(key)
            report.issues.extend(module.pop("issues", []))
            report.modules[namespace][module["name"]] = module

    presets = data.get("presets", [])
    if not isinstance(presets, list):
        report.issues.append(
            ModuleIssue("<presets>", "presets", "must be a list of presets")
        )
        presets = []
    report.presets = presets
    report.issues.extend(_validate_presets(presets, report.modules))
    return report


def _validate_presets(presets: list, modules: dict) -> list:
    issues = []
    seen = set()
    for preset in presets:
        if not isinstance(preset, dict):
            issues.append(ModuleIssue("<presets>", "presets", "must be a JSON object"))
            continue
        name = preset.get("name", "<unnamed>")
        if not isinstance(name, str) or not NAMESPACE_RE.match(name):
            issues.append(
                ModuleIssue(
                    str(name), "preset name", "must match ^[a-z][a-z0-9_]{1,32}$"
                )
            )
        if name in seen:
            issues.append(ModuleIssue(str(name), "preset name", "is duplicated"))
        seen.add(name)
        if preset.get("target_os") not in TARGET_OS:
            issues.append(
                ModuleIssue(
                    str(name), "target_os", f"must be one of {', '.join(TARGET_OS)}"
                )
            )
        members = preset.get("modules")
        if not isinstance(members, list) or not members:
            issues.append(ModuleIssue(str(name), "modules", "must be a non-empty list"))
            continue
        for member in members:
            if not isinstance(member, str) or "/" not in member:
                issues.append(
                    ModuleIssue(
                        str(name),
                        "modules",
                        f"{member!r} must look like 'namespace/Module_Name'",
                    )
                )
                continue
            namespace, _, module_name = member.partition("/")
            if namespace not in modules:
                issues.append(
                    ModuleIssue(str(name), "modules", f"unknown namespace {namespace!r}")
                )
                continue
            if module_name.lower() == "all":
                continue
            if module_name not in modules[namespace]:
                issues.append(
                    ModuleIssue(str(name), "modules", f"unknown module {member!r}")
                )
    return issues
