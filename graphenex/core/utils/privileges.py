"""Privilege helpers used by the hardening engine and the CLI."""

from __future__ import annotations

import os


def is_elevated() -> bool:
    """Return ``True`` when running as root (POSIX) or administrator (Windows)."""

    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except OSError:
        return False


def elevation_hint() -> str:
    """Human readable advice for the current platform."""

    if os.name == "nt":
        return "Run grapheneX from an elevated (Administrator) prompt."
    return "Re-run grapheneX with sudo (or as root)."


def current_user() -> str:
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or os.environ.get(
        "USERNAME", "unknown"
    )
