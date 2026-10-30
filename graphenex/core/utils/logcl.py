"""Logging for grapheneX.

Logs go to *stderr* so that stdout stays machine readable (``--json``) and can
be piped safely. Colour is only used on a TTY and is disabled when ``NO_COLOR``
is set or ``TERM=dumb``, which keeps the output readable in CI, screen readers
and log collectors.
"""

from __future__ import annotations

import logging
import os
import sys

DEFAULT_FORMAT = "%(asctime)s > %(name)s > %(levelname)s > %(message)s"

_COLORS = {
    "DEBUG": "\033[35m",
    "INFO": "\033[36m",
    "WARNING": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[1;31m",
}
_NAME_COLOR = "\033[34m"
_RESET = "\033[0m"


def color_enabled(stream=None) -> bool:
    """Return ``True`` when ANSI colour should be emitted."""

    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream if stream is not None else sys.stderr
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


class GraphenexFormatter(logging.Formatter):
    """Formatter that optionally colours the level and logger name."""

    def __init__(self, fmt=DEFAULT_FORMAT, datefmt="%H:%M:%S", color=False):
        super().__init__(fmt, datefmt)
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        if not self.color:
            return super().format(record)
        original_name, original_level = record.name, record.levelname
        try:
            record.name = f"{_NAME_COLOR}{original_name}{_RESET}"
            record.levelname = (
                f"{_COLORS.get(original_level, '')}{original_level}{_RESET}"
            )
            return super().format(record)
        finally:
            record.name, record.levelname = original_name, original_level


class GraphenexLogger(logging.Logger):
    """
    Logger used throughout grapheneX.

    Keeps the small API the project used to expose (``info``, ``warn``,
    ``error``, ``debug``) while relying only on the standard library.
    """

    LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    def __init__(self, name, level="INFO", format=DEFAULT_FORMAT):
        level_name = str(level).upper()
        super().__init__(name, self.LEVELS.get(level_name, logging.INFO))
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            GraphenexFormatter(
                fmt=format, datefmt="%H:%M:%S", color=color_enabled(sys.stderr)
            )
        )
        self.addHandler(handler)
        self.propagate = False

    def warn(self, msg, *args, **kwargs):
        """Backwards-compatible alias for :meth:`warning`."""

        self.warning(msg, *args, **kwargs)


def configure(level="INFO") -> None:
    """Adjust the level of every grapheneX logger created so far."""

    level_value = GraphenexLogger.LEVELS.get(str(level).upper(), logging.INFO)
    for logger in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(logger, GraphenexLogger):
            logger.setLevel(level_value)
            for handler in logger.handlers:
                handler.setLevel(level_value)
