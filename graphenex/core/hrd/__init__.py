"""
Hardening module: check, apply and -- always -- revert.

A :class:`HardenMethod` wraps one validated module definition. The public API
is intentionally small:

``check()``   run the audit command; ``result.ok`` means "already compliant".
``apply()``   take backups, run the hardening command, record everything.
``revert()``  restore backups and run the revert command for a previous run.

``apply()`` refuses to run a module that cannot be reverted unless the caller
explicitly passes ``allow_unrevertible=True`` (CLI: ``--allow-unrevertible``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from graphenex.core.hrd.exec import LinuxExec, WinExec
from graphenex.core.hrd.journal import Journal, RunRecord, new_run_id, sha256_text
from graphenex.core.hrd.schema import normalize_module
from graphenex.core.utils import privileges

try:  # pragma: no cover - version is only cosmetic metadata
    from graphenex import __version__ as FRAMEWORK_VERSION
except Exception:  # pragma: no cover
    FRAMEWORK_VERSION = "unknown"

_PUBLIC_FIELDS = (
    "name",
    "desc",
    "command",
    "check_command",
    "revert_command",
    "files",
    "shell",
    "timeout",
    "require_superuser",
    "require_restart",
    "target_os",
    "cis",
    "nist",
    "tags",
    "risk",
    "notes",
    "probe",
    "irreversible",
    "irreversible_reason",
    "idempotent",
    "requires",
)


def _executor(target_os: str):
    if target_os == "win":
        return WinExec()
    return LinuxExec()


@dataclass
class ApplyOutcome:
    module: str
    run_id: str = ""
    result: Optional[object] = None
    backups: list = field(default_factory=list)
    journaled: bool = False
    dry_run: bool = False
    already_compliant: bool = False
    verified: Optional[bool] = None
    restart_required: bool = False
    pre_state: str = ""
    messages: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if self.result is None:
            return False
        return bool(getattr(self.result, "ok", False)) or self.already_compliant

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "run_id": self.run_id,
            "ok": self.ok,
            "already_compliant": self.already_compliant,
            "dry_run": self.dry_run,
            "journaled": self.journaled,
            "verified": self.verified,
            "restart_required": self.restart_required,
            "pre_state": self.pre_state,
            "result": self.result.to_dict() if hasattr(self.result, "to_dict") else None,
            "backups": [
                item.to_dict() if hasattr(item, "to_dict") else dict(item)
                for item in self.backups
            ],
            "messages": list(self.messages),
        }


@dataclass
class RevertOutcome:
    module: str
    run_id: str = ""
    revert_run_id: str = ""
    result: Optional[object] = None
    restored: list = field(default_factory=list)
    verified: Optional[bool] = None
    dry_run: bool = False
    pre_state: str = ""
    error: str = ""
    messages: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        if self.error:
            return False
        if self.result is not None and not getattr(self.result, "ok", False):
            return False
        return all(item.get("ok") for item in self.restored) if self.restored else True

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "run_id": self.run_id,
            "revert_run_id": self.revert_run_id,
            "ok": self.ok,
            "dry_run": self.dry_run,
            "verified": self.verified,
            "pre_state": self.pre_state,
            "error": self.error,
            "result": self.result.to_dict() if hasattr(self.result, "to_dict") else None,
            "restored": list(self.restored),
            "messages": list(self.messages),
        }


class HardenMethod:
    """A single, validated hardening module."""

    def __init__(self, **kwargs):
        raw = dict(kwargs)
        namespace = raw.pop("namespace", raw.pop("ns", ""))
        if "schema_version" not in raw:
            raw = normalize_module(raw)
        aliases = {"check": "check_command", "revert": "revert_command"}
        for key, value in raw.items():
            setattr(self, aliases.get(key, key), value)
        self.namespace = namespace
        self.executor = _executor(self.target_os)

    # -- identity --------------------------------------------------------
    @property
    def qualified_name(self) -> str:
        return f"{self.namespace}/{self.name}" if self.namespace else self.name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.__str__()

    @property
    def revertible(self) -> bool:
        return bool(self.revert_command or self.files) and not self.irreversible

    @property
    def revert_strategy(self) -> str:
        revert = getattr(self, "revert_command", "")
        files = getattr(self, "files", [])
        if revert and files:
            return "command+files"
        if revert:
            return "command"
        if files:
            return "files"
        return "none"

    def to_dict(self) -> dict:
        data = {
            key: value for key, value in self.__dict__.items() if key in _PUBLIC_FIELDS
        }
        data["namespace"] = self.namespace
        data["qualified_name"] = self.qualified_name
        data["revertible"] = self.revertible
        data["revert_strategy"] = self.revert_strategy
        data["check"] = self.check_command
        data["revert"] = self.revert_command
        return data

    # -- execution -------------------------------------------------------
    def _run(self, command: str, dry_run: bool = False):
        return self.executor.run_cmd(
            command, shell=self.shell, timeout=self.timeout, dry_run=dry_run
        )

    def _require_superuser(self) -> None:
        if self.require_superuser and not privileges.is_elevated():
            raise PermissionError(
                f"{self.qualified_name} requires administrator/root privileges. "
                + privileges.elevation_hint()
            )

    def check(self, dry_run: bool = False):
        """Run the audit command. ``result.ok`` means the module is compliant."""

        return self._run(self.check_command, dry_run=dry_run)

    def _probe(self, dry_run: bool = False) -> str:
        """Record the pre-change state when the module defines a probe."""

        probe = getattr(self, "probe", "")
        if not probe:
            return ""

    def apply(
        self,
        dry_run: bool = False,
        journal: Optional[Journal] = None,
        force: bool = False,
        allow_unrevertible: bool = False,
        allow_irreversible: bool = False,
        journal_writer: bool = True,
    ) -> ApplyOutcome:
        """Apply the hardening command, taking backups first."""

        outcome = ApplyOutcome(
            module=self.qualified_name,
            dry_run=dry_run,
            restart_required=bool(self.require_restart),
        )

        if self.irreversible and not allow_irreversible:
            raise PermissionError(
                f"{self.qualified_name} is marked irreversible "
                f"({self.irreversible_reason or 'no reason given'}). "
                "Re-run with --allow-irreversible to accept that this change "
                "cannot be undone."
            )
        if not self.revertible and not allow_unrevertible:
            raise PermissionError(
                f"{self.qualified_name} has no revert definition and is not "
                "marked irreversible, so grapheneX will not apply it. "
                "Add a 'revert'/'files' definition to the module or pass "
                "--allow-unrevertible to override (not recommended)."
            )

        self._require_superuser()

        journal = journal or Journal()
        outcome.pre_state = self._probe(dry_run=dry_run)

        if self.check_command and not force:
            pre = self.check(dry_run=dry_run)
            if pre.ok:
                outcome.already_compliant = True
                outcome.result = pre
                outcome.run_id = new_run_id()
                outcome.messages.append(
                    f"{self.qualified_name} already reports compliant; nothing to do "
                    "(use --force to apply anyway)."
                )
                return outcome

        run_id = new_run_id()
        outcome.run_id = run_id
        if self.files:
            outcome.backups = journal.backups.capture(run_id, self.files)

        result = self._run(self.command, dry_run=dry_run)
        outcome.result = result

        if self.check_command and not dry_run and result.ok:
            try:
                outcome.verified = self.check().ok
            except Exception:  # pragma: no cover - defensive
                outcome.verified = None

        if journal_writer and not dry_run:
            record = RunRecord(
                run_id=run_id,
                action="apply",
                module=self.qualified_name,
                namespace=self.namespace,
                name=self.name,
                target_os=self.target_os,
                user=privileges.current_user(),
                elevated=privileges.is_elevated(),
                command=self.command,
                command_sha256=sha256_text(self.command),
                check_command=self.check_command,
                revert_command=self.revert_command,
                shell=self.shell,
                returncode=result.returncode,
                ok=result.ok,
                timed_out=result.timed_out,
                duration=result.duration,
                stdout=result.stdout,
                stderr=result.stderr,
                pre_state=outcome.pre_state,
                backups=outcome.backups,
                requires_restart=bool(self.require_restart),
                framework_version=str(FRAMEWORK_VERSION),
                extra={
                    "verified": outcome.verified,
                    "cis": list(self.cis),
                    "risk": self.risk,
                },
            )
            journal.append(record)
            outcome.journaled = True
        return outcome

    def revert(
        self,
        run_id: Optional[str] = None,
        journal: Optional[Journal] = None,
        dry_run: bool = False,
        record: Optional[RunRecord] = None,
        journal_writer: bool = True,
    ) -> RevertOutcome:
        """Undo a previous apply: run the revert command, then restore backups."""

        journal = journal or Journal()
        outcome = RevertOutcome(module=self.qualified_name, dry_run=dry_run)

        if record is None:
            if run_id in (None, "", "last"):
                pending = journal.pending(module=self.qualified_name)
                record = pending[0] if pending else None
                if record is None:
                    outcome.error = (
                        f"no pending (not yet reverted) run found for "
                        f"{self.qualified_name}"
                    )
                    return outcome
            else:
                record = journal.get(run_id)
                if record is None:
                    outcome.error = f"unknown run id: {run_id}"
                    return outcome

        outcome.run_id = record.run_id
        outcome.pre_state = record.pre_state
        if record.action != "apply":
            outcome.error = (
                f"run {record.run_id} is a {record.action!r} record, only applied "
                "runs can be reverted"
            )
            return outcome
        if record.reverted:
            outcome.error = (
                f"run {record.run_id} was already reverted by "
                f"{record.reverted_by or 'another run'}"
            )
            return outcome

        messages = outcome.messages
        if record.requires_restart:
            messages.append(
                "The original change required a restart; revert it the same way "
                "for the previous configuration to take effect."
            )
        if record.pre_state:
            messages.append(f"Pre-change state recorded at apply time: {record.pre_state}")

        if record.revert_command:
            result = self._run(record.revert_command, dry_run=dry_run)
            outcome.result = result
            if not result.ok:
                outcome.error = f"revert command failed: {result.summary()}"
        if record.backups:
            if dry_run:
                outcome.restored = [
                    {"path": entry.path, "ok": True, "action": "would restore", "drifted": False}
                    for entry in record.backups
                ]
            else:
                outcome.restored = journal.backups.restore(record.backups)
                drifted = [item["path"] for item in outcome.restored if item.get("drifted")]
                if drifted:
                    messages.append(
                        "Restored files had been modified after hardening: "
                        + ", ".join(drifted)
                    )

        if not dry_run and self.check_command:
            # Verification after a revert means: the module no longer reports
            # compliant, i.e. the hardening is really gone.
            try:
                outcome.verified = not self.check().ok
            except Exception:  # pragma: no cover - defensive
                outcome.verified = None

        if journal_writer and not dry_run:
            revert_run_id = new_run_id()
            outcome.revert_run_id = revert_run_id
            revert_record = RunRecord(
                run_id=revert_run_id,
                action="revert",
                module=record.module,
                namespace=record.namespace,
                name=record.name,
                target_os=record.target_os,
                user=privileges.current_user(),
                elevated=privileges.is_elevated(),
                command=record.revert_command,
                command_sha256=sha256_text(record.revert_command or ""),
                shell=self.shell,
                returncode=(
                    outcome.result.returncode if outcome.result is not None else 0
                ),
                ok=outcome.ok,
                duration=(
                    outcome.result.duration if outcome.result is not None else 0.0
                ),
                stdout=(
                    outcome.result.stdout if outcome.result is not None else ""
                ),
                stderr=(
                    outcome.result.stderr if outcome.result is not None else ""
                ),
                pre_state=record.pre_state,
                backups=record.backups,
                parent_run_id=record.run_id,
                framework_version=str(FRAMEWORK_VERSION),
                extra={
                    "restored": outcome.restored,
                    "verified": outcome.verified,
                    "error": outcome.error,
                },
            )
            journal.append(revert_record)
            record.reverted = True
            record.reverted_at = revert_record.timestamp
            record.reverted_by = revert_run_id
        return outcome

    # -- backwards compatibility ----------------------------------------
    def execute_command(self):
        """Legacy helper: apply the module and return its stdout."""

        outcome = self.apply(allow_unrevertible=True, allow_irreversible=True)
        if not outcome.ok:
            raise PermissionError(
                f"Command for {self.qualified_name} failed: {outcome.result.summary()}"
            )
        return outcome.result.stdout


        result = self._run(probe, dry_run=dry_run)
        return result.output().strip()

