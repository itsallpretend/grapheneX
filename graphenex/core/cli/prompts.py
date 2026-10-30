"""Small, standard-library prompt helpers.

``PyInquirer`` was unmaintained for years, pinned an ancient ``prompt_toolkit``
and needed a ``sed`` patch on every install (see the Dockerfile history). These
prompt functions cover the three interactions the CLI needs (confirm, select,
text) and are deliberately line based so they work in plain terminals, over
serial consoles, through ``script``/``expect`` and with screen readers.

Non-interactive use is first class: if stdin is not a TTY, prompts fail with a
clear message instead of hanging, and ``--yes``/``GRAPHENEX_ASSUME_YES=1``
answers every confirmation with ``yes``.
"""

from __future__ import annotations

import os
import sys

MAX_ATTEMPTS = 5


class PromptError(Exception):
    """Raised when a prompt cannot be answered (EOF, no TTY, cancelled)."""


def assume_yes() -> bool:
    """Return ``True`` when confirmations should be answered automatically."""

    value = os.environ.get("GRAPHENEX_ASSUME_YES", "")
    return value.strip().lower() in ("1", "true", "yes", "on")


def is_interactive() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (AttributeError, ValueError):
        return False


def _read(prompt_text: str) -> str:
    try:
        return input(prompt_text)
    except EOFError as exc:
        raise PromptError(
            "no more input available (stdin closed); use the --yes flag or the "
            "non-interactive CLI options for unattended runs"
        ) from exc
    except KeyboardInterrupt as exc:
        raise PromptError("cancelled by user") from exc


def confirm(message: str, default: bool = False, auto: bool | None = None) -> bool:
    """Ask a yes/no question."""

    if auto is None:
        auto = assume_yes()
    if auto:
        return True
    suffix = "[Y/n]" if default else "[y/N]"
    for _ in range(MAX_ATTEMPTS):
        answer = _read(f"{message} {suffix} ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")
    raise PromptError("too many invalid answers")


def select(message: str, choices, default: int = 0, cancel_hint: bool = True) -> str:
    """Show a numbered list and return the chosen entry."""

    choices = [str(choice) for choice in choices]
    if not choices:
        raise PromptError("nothing to choose from")
    if assume_yes():
        return choices[default if 0 <= default < len(choices) else 0]

    print(message)
    for index, choice in enumerate(choices, start=1):
        marker = " (default)" if index - 1 == default else ""
        print(f"  {index}. {choice}{marker}")
    if cancel_hint:
        print("  q. cancel")

    for _ in range(MAX_ATTEMPTS):
        answer = _read("> ").strip()
        if not answer:
            return choices[default if 0 <= default < len(choices) else 0]
        if answer.lower() in ("q", "quit", "cancel"):
            raise PromptError("cancelled by user")
        if answer.isdigit():
            index = int(answer) - 1
            if 0 <= index < len(choices):
                return choices[index]
        matches = [choice for choice in choices if choice.lower() == answer.lower()]
        if not matches:
            matches = [choice for choice in choices if choice.lower().startswith(answer.lower())]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            print("Ambiguous answer: " + ", ".join(matches))
        else:
            print("Invalid choice, try again.")
    raise PromptError("too many invalid answers")


def text(
    message: str,
    default: str = "",
    validate=None,
    allow_empty: bool = False,
    secret: bool = False,
) -> str:
    """Ask for a line of text, optionally validating it."""

    suffix = f" [{default}]" if default else ""
    for _ in range(MAX_ATTEMPTS):
        if secret:
            try:
                import getpass

                answer = getpass.getpass(message + suffix + ": ")
            except (EOFError, KeyboardInterrupt) as exc:
                raise PromptError("cancelled by user") from exc
        else:
            answer = _read(message + suffix + ": ").strip()
        if not answer:
            if default:
                return default
            if allow_empty:
                return ""
            print("A value is required.")
            continue
        if validate:
            problem = validate(answer)
            if problem:
                print(problem)
                continue
        return answer
    raise PromptError("too many invalid answers")
