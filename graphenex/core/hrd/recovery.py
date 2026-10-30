"""Revert operations that only need the journal, not the module file.

Reverting must keep working when:

* the module was renamed, edited or deleted from ``modules.json`` after apply;
* grapheneX is upgraded between apply and revert;
* the user is on a different machine with the same state directory.

That is why the journal stores the commands, their digest, the shell flag and
the backup locations. :func:`revert_record` replays that recorded information
instead of trusting today's module definition.
"""

from __future__ import annotations

import pathlib
from typing import Optional

from graphenex.core.hrd.exec import DEFAULT_TIMEOUT, LinuxExec, WinExec
from graphenex.core.hrd.journal import (
    Journal,
    RunRecord,
    excerpt,
    new_run_id,
    sha256_file,
    sha256_text,
)
from graphenex.core.utils import privileges

# Imported lazily to avoid an import cycle at module load time.
def _outcome(**kwargs):
    from graphenex.core.hrd import RevertOutcome

    return RevertOutcome(**kwargs)


def executor_for(record: RunRecord):
    return WinExec() if record.target_os == "win" else LinuxExec()


def pending_records(journal: Optional[Journal] = None, module: Optional[str] = None):
    journal = journal or Journal()
    return journal.pending(module=module)


def resolve_runs(journal: Journal, spec: Optional[str]) -> list[RunRecord]:
    """Resolve ``last``, ``all``, a run id or a module target to records."""

    spec = (spec or "last").strip()
    pending = journal.pending()
    if spec == "last":
        return pending[:1]
    if spec == "all":
        return pending

    record = journal.get(spec)
    if record is not None:
        return [record]

    matches = [
        item for item in pending
        if item.module.lower() == spec.lower()
        or item.name.lower() == spec.lower()
        or item.module.lower().endswith("/" + spec.lower())
    ]
    return matches


def revert_record(
    record: RunRecord,
    journal: Optional[Journal] = None,
    dry_run: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    journal_writer: bool = True,
):
    """Revert one applied run using the data stored in the journal."""

    journal = journal or Journal()
    outcome = _outcome(
        module=record.module,
        run_id=record.run_id,
        dry_run=dry_run,
        pre_state=record.pre_state,
    )

    if record.action != "apply":
        outcome.error = f"run {record.run_id} is a {record.action!r} record"
        return outcome
    if record.reverted:
        outcome.error = (
            f"run {record.run_id} was already reverted by "
            f"{record.reverted_by or 'another run'}"
        )
        return outcome
    if not record.revert_command and not record.backups:
        outcome.error = (
            f"run {record.run_id} has neither a revert command nor backups "
            "in the journal"
        )
        return outcome

    executor = executor_for(record)
    if record.requires_restart:
        outcome.messages.append(
            "The original change required a restart; restart the affected "
            "service or host for the previous configuration to take effect."
        )
    if record.pre_state:
        outcome.messages.append(
            f"Pre-change state recorded at apply time: {record.pre_state}"
        )

    post_hashes = (record.extra or {}).get("post_hashes") or {}
    current_hashes = {}
    if post_hashes and not dry_run:
        for entry in record.backups:
            if entry.kind != "file":
                continue
            try:
                current_hashes[entry.path] = sha256_file(pathlib.Path(entry.path))
            except OSError:
                current_hashes[entry.path] = ""

    if record.backups:
        if dry_run:
            outcome.restored = [
                {
                    "path": entry.path,
                    "ok": True,
                    "action": "would restore",
                    "drifted": False,
                }
                for entry in record.backups
            ]
        else:
            outcome.restored = journal.backups.restore(record.backups)
            drifted = []
            for item in outcome.restored:
                expected = post_hashes.get(item["path"])
                if expected and current_hashes.get(item["path"], expected) != expected:
                    item["drifted"] = True
                    drifted.append(item["path"])
            if drifted:
                outcome.messages.append(
                    "Files had been modified after hardening and were "
                    "overwritten while reverting: " + ", ".join(drifted)
                )

    if record.revert_command:
        result = executor.run_cmd(
            record.revert_command, shell=record.shell, timeout=timeout, dry_run=dry_run
        )
        outcome.result = result
        if not result.ok:
            outcome.error = f"revert command failed: {result.summary()}"

    if record.check_command and not dry_run:
        verification = executor.run_cmd(
            record.check_command, shell=record.shell, timeout=timeout
        )
        # The module must no longer report compliant after a revert.
        outcome.verified = not verification.ok

    if journal_writer and not dry_run:
        outcome.revert_run_id = new_run_id()
        revert_record_entry = RunRecord(
            run_id=outcome.revert_run_id,
            action="revert",
            module=record.module,
            namespace=record.namespace,
            name=record.name,
            target_os=record.target_os,
            user=privileges.current_user(),
            elevated=privileges.is_elevated(),
            command=record.revert_command,
            command_sha256=sha256_text(record.revert_command or ""),
            shell=record.shell,
            returncode=outcome.result.returncode if outcome.result else 0,
            ok=outcome.ok,
            duration=outcome.result.duration if outcome.result else 0.0,
            stdout=excerpt(outcome.result.stdout) if outcome.result else "",
            stderr=excerpt(outcome.result.stderr) if outcome.result else "",
            pre_state=record.pre_state,
            backups=record.backups,
            parent_run_id=record.run_id,
            extra={"restored": outcome.restored, "verified": outcome.verified},
        )
        journal.append(revert_record_entry)
        record.reverted = True
        record.reverted_at = revert_record_entry.timestamp
        record.reverted_by = outcome.revert_run_id
    return outcome
