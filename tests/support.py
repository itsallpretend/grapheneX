"""Shared test helpers."""

from __future__ import annotations

import os
import pathlib
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULES_FILE = REPO_ROOT / "graphenex" / "modules.json"


def isolated_state(case: unittest.TestCase) -> pathlib.Path:
    """Point grapheneX at a throw-away state directory for one test."""

    directory = pathlib.Path(tempfile.mkdtemp(prefix="gx-test-state-"))
    previous = os.environ.get("GRAPHENEX_STATE_DIR")
    os.environ["GRAPHENEX_STATE_DIR"] = str(directory)

    def restore():
        if previous is None:
            os.environ.pop("GRAPHENEX_STATE_DIR", None)
        else:
            os.environ["GRAPHENEX_STATE_DIR"] = previous

    case.addCleanup(restore)
    return directory


def workdir(case: unittest.TestCase) -> pathlib.Path:
    directory = pathlib.Path(tempfile.mkdtemp(prefix="gx-test-work-"))
    case.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
    return directory
