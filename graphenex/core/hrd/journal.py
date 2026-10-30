"""
Run journal, backups and audit trail.

Every apply/check/revert operation appends a hash-chained JSON record to
``$GRAPHENEX_STATE_DIR/journal.jsonl`` (mode 0600, directory 0700). The record
for an apply contains the exact commands that were executed, their digest and
the paths of the backups that were taken, which is what makes ``revert``
deterministic rather than best-effort.

The hash chain (``prev``/``hash``) makes silent tampering detectable: removing
or editing a record breaks the chain for every following record.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import pathlib
import shutil
import stat
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Optional

from graphenex.core.utils import paths

JOURNAL_SCHEMA = 1
MAX_STORED_BYTES = 8 * 1024 * 1024
EXCERPT_LIMIT = 4000


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_run_id() -> str:
    """Short, sortable-enough identifier for a single hardening run."""

    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def excerpt(text: str) -> str:
    text = text or ""
    if len(text) > EXCERPT_LIMIT:
        return text[:EXCERPT_LIMIT] + "\n[excerpt truncated]"
    return text


@dataclass
class BackupEntry:
    """A single file/directory snapshot taken before a change."""

    path: str
    existed: bool
    kind: str
    mode: Optional[int] = None
    sha256: str = ""
    stored: str = ""
    size: int = 0
    missing: bool = False
    error: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "BackupEntry":
        known = {key: data.get(key) for key in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in known.items() if value is not None})

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "existed": self.existed,
            "kind": self.kind,
            "mode": self.mode,
            "sha256": self.sha256,
            "stored": self.stored,
            "size": self.size,
            "missing": self.missing,
        }


@dataclass
class RunRecord:
    """One journal entry."""

    run_id: str
    action: str
    module: str
    namespace: str = ""
    name: str = ""
    target_os: str = ""
    timestamp: float = field(default_factory=time.time)
    user: str = ""
    elevated: bool = False
    command: str = ""
    command_sha256: str = ""
    check_command: str = ""
    revert_command: str = ""
    shell: bool = False
    returncode: int = 0
    ok: bool = False
    timed_out: bool = False
    duration: float = 0.0
    stdout: str = ""
    stderr: str = ""
    pre_state: str = ""
    backups: list = field(default_factory=list)
    reverted: bool = False
    reverted_at: Optional[float] = None
    reverted_by: str = ""
    parent_run_id: str = ""
    requires_restart: bool = False
    framework_version: str = ""
    extra: dict = field(default_factory=dict)
    prev: str = ""
    hash: str = ""
    schema: int = JOURNAL_SCHEMA

    @classmethod
    def from_dict(cls, data: dict) -> "RunRecord":
        data = dict(data)
        data["backups"] = [BackupEntry.from_dict(item) for item in data.get("backups", [])]
        known = {}
        for key in cls.__dataclass_fields__:  # type: ignore[attr-defined]
            if key in data:
                known[key] = data[key]
        return cls(**known)

    def body(self) -> dict:
        derived = ("hash", "backups", "reverted", "reverted_at", "reverted_by")
        data = {
            key: getattr(self, key)
            for key in self.__dataclass_fields__  # type: ignore[attr-defined]
            if key not in derived
        }
        data["backups"] = [
            item.to_dict() if isinstance(item, BackupEntry) else item
            for item in self.backups
        ]
        return data

    def seal(self, prev_hash: str) -> "RunRecord":
        self.prev = prev_hash
        self.hash = sha256_text(_canonical(self.body()))
        return self

    def to_dict(self) -> dict:
        data = self.body()
        data["hash"] = self.hash
        return data

    def summary_row(self) -> tuple:
        state = "reverted" if self.reverted else ("applied" if self.ok else "failed")
        if self.action == "check":
            state = "compliant" if self.ok else "drift"
        elif self.action == "revert":
            state = "reverted" if self.ok else "revert-failed"
        return (
            self.run_id,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            self.module,
            state,
        )



class BackupManager:
    """Snapshot files/directories so that a module can be reverted exactly."""

    def __init__(self, root: Optional[pathlib.Path] = None):
        self.root = pathlib.Path(root) if root else paths.state_dir() / "backups"

    # -- capture ---------------------------------------------------------
    @staticmethod
    def expand(paths_in: Iterable[str]) -> list[str]:
        """
        Expand globs (``/etc/ssh/ssh_host_*_key``) and de-duplicate paths.

        Symlinks are intentionally *not* followed: a snapshot of a symlink is
        recorded as a symlink and restored as one.
        """

        expanded: list[str] = []
        seen: set[str] = set()
        for pattern in paths_in or []:
            if any(char in pattern for char in "*?["):
                matches = sorted(glob.glob(pattern))
            else:
                matches = [pattern]
            for match in matches:
                normalised = os.path.normpath(os.path.abspath(match))
                if normalised in seen:
                    continue
                seen.add(normalised)
                expanded.append(normalised)
        return expanded

    def capture(self, run_id: str, paths_in: Iterable[str]) -> list[BackupEntry]:
        """Copy every path into ``backups/<run_id>/`` and record its metadata."""

        entries: list[BackupEntry] = []
        target_dir = self.root / run_id
        for index, raw_path in enumerate(self.expand(paths_in)):
            path = pathlib.Path(raw_path)
            entry = BackupEntry(path=str(path), existed=False, kind="missing")
            try:
                info = path.lstat()
            except FileNotFoundError:
                entries.append(entry)
                continue
            except OSError as exc:
                entry.missing = True
                entry.kind = "error"
                entry.error = str(exc)
                entries.append(entry)
                continue

            entry.existed = True
            entry.mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                entry.kind = "symlink"
                entry.stored = os.readlink(path)
                entry.sha256 = sha256_text(entry.stored)
                entries.append(entry)
                continue
            if stat.S_ISDIR(info.st_mode):
                entry.kind = "dir"
                entries.append(entry)
                continue
            if not stat.S_ISREG(info.st_mode):
                entry.kind = "other"
                entries.append(entry)
                continue

            entry.kind = "file"
            entry.size = info.st_size
            try:
                entry.sha256 = sha256_file(path)
                paths.ensure_private_dir(target_dir)
                stored_path = target_dir / f"{index:04d}-{path.name}"
                shutil.copy2(path, stored_path, follow_symlinks=False)
                os.chmod(stored_path, 0o600)
                entry.stored = str(stored_path)
            except OSError as exc:
                entry.missing = True
                entry.error = str(exc)
            entries.append(entry)
        return entries

    # -- restore ---------------------------------------------------------
    def _stored_path(self, entry: BackupEntry) -> pathlib.Path:
        stored = pathlib.Path(entry.stored).resolve()
        root = self.root.resolve()
        if root not in stored.parents:
            raise ValueError(
                f"refusing to restore from outside the backup root: {stored}"
            )
        return stored

    def restore(self, entries: Iterable[BackupEntry]) -> list[dict]:
        """Put every path back into the state recorded by :meth:`capture`."""

        restored: list[dict] = []
        for entry in entries:
            result = {
                "path": entry.path,
                "ok": False,
                "action": "none",
                "drifted": False,
                "error": "",
            }
            path = pathlib.Path(entry.path)
            try:
                if entry.kind == "missing":
                    if path.is_symlink() or path.exists():
                        if path.is_dir() and not path.is_symlink():
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                        result["action"] = "removed"
                    result["ok"] = True
                elif entry.kind == "dir":
                    if not path.is_dir():
                        path.mkdir(parents=True, exist_ok=True)
                        result["action"] = "created"
                    if entry.mode is not None:
                        os.chmod(path, entry.mode)
                    result["ok"] = True
                elif entry.kind == "symlink":
                    if path.is_symlink() or path.exists():
                        path.unlink()
                    os.symlink(entry.stored, path)
                    result["action"] = "symlink"
                    result["ok"] = True
                elif entry.kind == "file":
                    if entry.missing:
                        result["error"] = entry.error or "backup was not stored"
                        restored.append(result)
                        continue
                    if path.is_file() and not path.is_symlink():
                        if sha256_file(path) != entry.sha256:
                            result["drifted"] = True
                    stored_path = self._stored_path(entry)
                    paths.ensure_private_dir(path.parent)
                    if path.exists() and path.is_dir():
                        shutil.rmtree(path)
                    shutil.copy2(stored_path, path, follow_symlinks=False)
                    if entry.mode is not None:
                        os.chmod(path, entry.mode)
                    result["action"] = "restored"
                    result["ok"] = True
                else:
                    result["error"] = f"unsupported backup kind {entry.kind!r}"
            except (OSError, ValueError) as exc:
                result["error"] = str(exc)
            restored.append(result)
        return restored


class Journal:
    """Append-only, hash-chained record of every hardening operation."""

    def __init__(
        self,
        path: Optional[pathlib.Path] = None,
        backup_root: Optional[pathlib.Path] = None,
    ):
        state = paths.ensure_private_dir(paths.state_dir())
        self.path = pathlib.Path(path) if path else state / "journal.jsonl"
        self.backups = BackupManager(backup_root)
        paths.ensure_private_dir(self.path.parent)
        self._cache: Optional[list[RunRecord]] = None

    # -- writing ---------------------------------------------------------
    def _last_hash(self) -> str:
        if not self.path.exists():
            return ""

        try:
            with open(self.path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                block = min(size, 65536)
                handle.seek(size - block)
                tail = handle.read().splitlines()
        except OSError:
            return ""
        for line in reversed(tail):
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(record, dict) and record.get("hash"):
                return record["hash"]
        return ""

    # -- reading ---------------------------------------------------------
    def records(self, refresh: bool = False) -> list[RunRecord]:
        """Return every record, with revert state folded in."""

        if self._cache is not None and not refresh:
            return list(self._cache)

        loaded: list[RunRecord] = []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        loaded.append(RunRecord.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, TypeError):
                        # A corrupt line must not hide the rest of the history.
                        continue
        except FileNotFoundError:
            pass

        reverted_by: dict[str, tuple[float, str]] = {}
        for record in loaded:
            if record.action == "revert" and record.ok and record.parent_run_id:
                reverted_by[record.parent_run_id] = (record.timestamp, record.run_id)
        for record in loaded:
            if record.action == "revert":
                continue
            match = reverted_by.get(record.run_id)
            if match:
                record.reverted = True
                record.reverted_at = match[0]
                record.reverted_by = match[1]

        self._cache = loaded
        return list(loaded)

    def get(self, run_id: str) -> Optional[RunRecord]:
        for record in self.records():
            if record.run_id == run_id:
                return record
        return None

    def latest(self, action: Optional[str] = None, module: Optional[str] = None):
        for record in reversed(self.records()):
            if action and record.action != action:
                continue
            if module and record.module.lower() != module.lower():
                continue
            return record
        return None

    def applied(self, include_reverted: bool = False, module: Optional[str] = None):
        result = []
        for record in self.records():
            if record.action != "apply" or not record.ok:
                continue
            if record.reverted and not include_reverted:
                continue
            if module and record.module.lower() != module.lower():
                continue
            result.append(record)
        return result

    def pending(self, module: Optional[str] = None):
        """Applied runs that have not been reverted yet (newest first)."""

        return list(reversed(self.applied(include_reverted=False, module=module)))

    def history(self, limit: int = 20):
        return list(reversed(self.records()))[: max(1, limit)]

    # -- integrity -------------------------------------------------------
    def verify_chain(self) -> tuple[bool, list[str]]:
        """Check that no record was modified or removed."""

        problems: list[str] = []
        previous = ""
        for index, record in enumerate(self.records(refresh=True)):
            expected = sha256_text(_canonical(record.body()))
            if record.prev != previous:
                problems.append(
                    f"record {index} ({record.run_id}): broken link to previous record"
                )
            if record.hash != expected:
                problems.append(f"record {index} ({record.run_id}): hash mismatch")
            previous = record.hash
        return (not problems, problems)

    def prune_backups(self, keep: int = 20) -> int:
        """Delete backup directories of old, already reverted runs."""

        removed = 0
        runs = [record for record in self.records() if record.action == "apply"]
        keep_ids = {record.run_id for record in runs[-keep:]}
        try:
            entries = sorted(
                (entry for entry in self.backups.root.iterdir() if entry.is_dir()),
                key=lambda entry: entry.stat().st_mtime,
            )
        except (FileNotFoundError, NotADirectoryError):
            return 0
        for entry in entries:
            if entry.name in keep_ids:
                continue
            if not any(record.run_id == entry.name and not record.reverted for record in runs):
                try:
                    shutil.rmtree(entry)
                    removed += 1
                except OSError:
                    pass
        return removed

    def append(self, record: RunRecord) -> RunRecord:
        record.schema = JOURNAL_SCHEMA
        record.seal(self._last_hash())
        line = _canonical(record.to_dict()) + "\n"
        with paths.secure_open(self.path, 0o600) as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        if self._cache is not None:
            self._cache.append(record)
        return record

