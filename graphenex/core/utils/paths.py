"""
Filesystem locations used by grapheneX.

All paths are resolved at call time (not import time) so they can be
overridden by environment variables. This module is intentionally
dependency-free so that the hardening engine can be used and tested
without the web dependencies installed.

Environment variables
---------------------
GRAPHENEX_STATE_DIR   Override the state directory (journal, backups, audit log).
GRAPHENEX_CONFIG_DIR  Override the configuration directory (.env, settings).
GRAPHENEX_MODULES    Override the path of ``modules.json``.
"""

from __future__ import annotations

import os
import pathlib
import tempfile

APP_NAME = "graphenex"


def _xdg_dir(env_var: str, fallback: str) -> pathlib.Path:
    """Return an XDG base directory, honouring ``env_var``."""

    value = os.environ.get(env_var)
    if value:
        return pathlib.Path(value).expanduser()
    return pathlib.Path.home() / fallback


def state_dir() -> pathlib.Path:
    """Directory for journals, backups and audit records (mode 0700)."""

    override = os.environ.get("GRAPHENEX_STATE_DIR")
    if override:
        return pathlib.Path(override).expanduser()
    return _xdg_dir("XDG_STATE_HOME", ".local/state") / APP_NAME


def config_dir() -> pathlib.Path:
    """Directory for configuration such as the Flask secret key."""

    override = os.environ.get("GRAPHENEX_CONFIG_DIR")
    if override:
        return pathlib.Path(override).expanduser()
    return _xdg_dir("XDG_CONFIG_HOME", ".config") / APP_NAME


def env_file() -> pathlib.Path:
    """Path of the ``.env`` file holding the Flask secret key."""

    return config_dir() / ".env"


def default_modules_file() -> pathlib.Path:
    """Path of the packaged ``modules.json`` file."""

    return pathlib.Path(__file__).absolute().parent.parent.parent / "modules.json"


def modules_file() -> pathlib.Path:
    """Path of the active ``modules.json`` file."""

    override = os.environ.get("GRAPHENEX_MODULES")
    if override:
        return pathlib.Path(override).expanduser()
    return default_modules_file()


def ensure_private_dir(path: pathlib.Path, mode: int = 0o700) -> pathlib.Path:
    """Create ``path`` (and parents) and make sure it is not group/world readable."""

    path = pathlib.Path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        current = path.stat().st_mode & 0o777
        if current != mode:
            os.chmod(path, mode)
    except OSError:
        # Best effort: read-only filesystems or exotic platforms.
        pass
    return path


def secure_open(path: pathlib.Path, mode: int = 0o600):
    """Open ``path`` for appending, creating it with restrictive permissions."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(str(path), flags, mode)
    try:
        os.fchmod(fd, mode)
    except (AttributeError, OSError):
        pass
    return os.fdopen(fd, "a", encoding="utf-8")


def atomic_write(path: pathlib.Path, data: str, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically with explicit permissions."""

    path = pathlib.Path(path)
    ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".gx-", suffix=".tmp")
    tmp_path = pathlib.Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def read_env_file(path: pathlib.Path | None = None) -> dict:
    """Parse a minimal ``KEY=VALUE`` env file (no shell expansion)."""

    path = pathlib.Path(path) if path else env_file()
    values: dict[str, str] = {}
    try:
        content = path.read_text(encoding="utf-8")
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return values
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def write_env_value(path: pathlib.Path, key: str, value: str) -> None:
    """Set ``key`` to ``value`` in an env file, preserving other keys."""

    path = pathlib.Path(path)
    values = read_env_file(path)
    values[key] = value
    body = "".join(f"{k}={v}\n" for k, v in values.items())
    atomic_write(path, body, mode=0o600)
