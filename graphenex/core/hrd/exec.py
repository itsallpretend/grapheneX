"""
Safe command execution primitives.

Design goals
------------
* No implicit shell. ``shell=True`` has to be requested explicitly by the
  module definition (``"shell": true`` in ``modules.json``) because a module
  is executable code and must be able to opt in to shell semantics.
* Never raise for a non-zero exit status. Hardening commands routinely fail
  ("file already hardened", "unit not installed") and callers need the exit
  status and stderr to decide what to do.
* Always bound execution with a timeout and kill the whole process group so a
  hung ``systemctl`` cannot block a hardening run forever.
* Run with a sanitised environment (no ``LD_PRELOAD``/``BASH_ENV`` injection)
  and with ``LC_ALL=C`` so that check commands produce stable output.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

DEFAULT_TIMEOUT = 120
MAX_TIMEOUT = 3600
OUTPUT_LIMIT = 64 * 1024

#: Variables that let a caller (or a compromised parent process) change the
#: behaviour of the commands we execute. They are removed from the child env.
UNSAFE_ENV_VARS = frozenset({
    "BASH_ENV",
    "ENV",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PYTHONPATH",
    "PYTHONSTARTUP",
})

#: Variables that may be referenced from an argv-style command string.
EXPANDABLE_VARS = ("USER", "LOGNAME", "HOME")


def sanitized_env(extra: Optional[dict] = None) -> dict:
    """Return a copy of ``os.environ`` with unsafe variables removed."""

    env = {k: v for k, v in os.environ.items() if k not in UNSAFE_ENV_VARS}
    env.setdefault("LC_ALL", "C")
    env.setdefault(
        "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env


def _expand_known_vars(token: str) -> str:
    """Expand ``$USER``/``$HOME``-style references without invoking a shell."""

    for name in EXPANDABLE_VARS:
        value = os.environ.get(name, "")
        token = token.replace("${" + name + "}", value).replace("$" + name, value)
    return token


def build_argv(command: str, shell: bool = False) -> list[str] | str:
    """
    Turn a module command into something ``subprocess`` can execute.

    Raises ``ValueError`` for empty or unparsable commands so that the caller
    can report a module validation error instead of a crash.
    """

    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if "\x00" in command:
        raise ValueError("command must not contain NUL bytes")
    if shell:
        return command
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"command cannot be parsed without a shell: {exc}") from exc
    if not argv:
        raise ValueError("command must contain at least one argument")
    return [_expand_known_vars(part) for part in argv]


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a single command execution."""

    command: str
    argv: tuple = ()
    shell: bool = False
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    dry_run: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error

    def output(self) -> str:
        """Combined, human-readable output."""

        chunks = [chunk for chunk in (self.stdout, self.stderr) if chunk]
        return "".join(chunks)

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "argv": list(self.argv),
            "shell": self.shell,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": round(self.duration, 3),
            "timed_out": self.timed_out,
            "dry_run": self.dry_run,
            "ok": self.ok,
            "error": self.error,
        }

    def summary(self, limit: int = 200) -> str:
        """One-line description used by the CLI and the journal."""

        if self.dry_run:
            return f"[dry-run] {self.command}"
        if self.error:
            return f"error: {self.error}"
        if self.timed_out:
            return f"timed out after {self.duration:.1f}s"
        if self.ok:
            text = (self.stdout or "").strip() or "ok"
        else:
            text = (self.stderr or self.stdout or "").strip() or (
                f"exit status {self.returncode}"
            )
        text = " ".join(text.split())
        if len(text) > limit:
            text = text[: limit - 3] + "..."
        return text


class OsExec:
    """Base class for platform command executors."""

    os_name = "linux"

    def run_cmd(
        self,
        cmd: str,
        shell: bool = False,
        timeout: int | float = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        dry_run: bool = False,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        raise NotImplementedError

    # -- helpers ---------------------------------------------------------
    def _timeout(self, timeout: int | float) -> float:
        try:
            timeout = float(timeout)
        except (TypeError, ValueError):
            return float(DEFAULT_TIMEOUT)
        if timeout <= 0:
            return float(DEFAULT_TIMEOUT)
        return min(timeout, float(MAX_TIMEOUT))

    @staticmethod
    def _truncate(data: bytes) -> str:
        if len(data) > OUTPUT_LIMIT:
            data = data[:OUTPUT_LIMIT] + b"\n[output truncated by grapheneX]"
        return data.decode("utf-8", "replace")

    def _spawn(
        self,
        command: str,
        shell: bool,
        timeout: int | float,
        env: Optional[dict],
        cwd: Optional[str],
        dry_run: bool,
        input_text: Optional[str],
        popen_kwargs: Optional[dict] = None,
    ) -> CommandResult:
        timeout = self._timeout(timeout)
        try:
            argv_or_cmd = build_argv(command, shell=shell)
        except ValueError as exc:
            return CommandResult(
                command=command, shell=shell, returncode=127, error=str(exc)
            )

        if dry_run:
            rendered = command if shell else shlex.join(argv_or_cmd)
            return CommandResult(
                command=command,
                argv=() if shell else tuple(argv_or_cmd),
                shell=shell,
                returncode=0,
                stdout=f"[dry-run] would execute: {rendered}\n",
                dry_run=True,
            )

        kwargs = dict(
            shell=shell,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=sanitized_env(env),
            cwd=cwd,
            close_fds=True,
        )
        kwargs.update(popen_kwargs or {})

        started = time.monotonic()
        try:
            proc = subprocess.Popen(argv_or_cmd, **kwargs)
        except FileNotFoundError:
            return CommandResult(
                command=command,
                shell=shell,
                returncode=127,
                error="executable not found",
                duration=time.monotonic() - started,
            )
        except PermissionError:
            return CommandResult(
                command=command,
                shell=shell,
                returncode=126,
                error="permission denied",
                duration=time.monotonic() - started,
            )
        except OSError as exc:
            return CommandResult(
                command=command,
                shell=shell,
                returncode=126,
                error=str(exc),
                duration=time.monotonic() - started,
            )


        timed_out = False
        try:
            stdout, stderr = proc.communicate(
                input=input_text.encode() if input_text is not None else None,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            self.terminate(proc)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = b"", b""

        return CommandResult(
            command=command,
            argv=() if shell else tuple(argv_or_cmd),
            shell=shell,
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=self._truncate(stdout or b""),
            stderr=self._truncate(stderr or b""),
            duration=time.monotonic() - started,
            timed_out=timed_out,
        )

    @staticmethod
    def terminate(proc: subprocess.Popen) -> None:
        """Terminate ``proc`` and its children."""

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (AttributeError, ProcessLookupError, PermissionError, OSError):
            proc.terminate()


class LinuxExec(OsExec):
    """Executor for POSIX systems."""

    os_name = "linux"

    def run_cmd(
        self,
        cmd: str,
        shell: bool = False,
        timeout: int | float = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        dry_run: bool = False,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        return self._spawn(
            cmd,
            shell=shell,
            timeout=timeout,
            env=env,
            cwd=cwd,
            dry_run=dry_run,
            input_text=input_text,
            popen_kwargs={"start_new_session": True},
        )


class WinExec(OsExec):
    """Executor for Windows."""

    os_name = "win"

    def run_cmd(
        self,
        cmd: str,
        shell: bool = False,
        timeout: int | float = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        dry_run: bool = False,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        popen_kwargs: dict = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        return self._spawn(
            cmd,
            shell=shell,
            timeout=timeout,
            env=env,
            cwd=cwd,
            dry_run=dry_run,
            input_text=input_text,
            popen_kwargs=popen_kwargs,
        )

    @staticmethod
    def terminate(proc: subprocess.Popen) -> None:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                return
            except (OSError, subprocess.SubprocessError):
                pass
        proc.terminate()

