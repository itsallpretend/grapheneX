"""Non-interactive CLI mode (``--list``, ``--check``, ``--apply``, ...).

This is the accessible path for automation: no prompts, stable exit codes and
optional JSON on stdout. Exit codes: ``0`` success/compliant, ``1`` drift or
failure, ``2`` usage error.
"""

from __future__ import annotations

import json
import sys

from graphenex.core.cli import prompts
from graphenex.core.cli.table import render_table
from graphenex.core.hrd.journal import Journal, RunRecord
from graphenex.core.hrd.recovery import resolve_runs, revert_record
from graphenex.core.utils import helpers
from graphenex.core.utils.logcl import GraphenexLogger

logger = GraphenexLogger(__name__)
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


class BatchError(Exception):
    """A usage problem that should be reported without a traceback."""


def _print_json(payload: dict) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


def _targets(args):
    try:
        modules = helpers.get_modules()
    except SystemExit:
        raise
    target = args.get("check") or args.get("apply") or helpers.TARGET_ALL
    try:
        return helpers.resolve_targets(target, modules)
    except KeyError as exc:
        raise BatchError(str(exc).strip(chr(39) + chr(34))) from exc


def cmd_validate(args) -> int:
    report = helpers.get_validation_report()
    if args.get("json"):
        _print_json({"command": "validate", **report.to_dict()})
    else:
        for issue in report.issues:
            print(issue)
        print(
            f"{sum(len(m) for m in report.modules.values())} modules in "
            f"{len(report.modules)} namespaces, {len(report.presets)} presets: "
            f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)"
        )
    return EXIT_OK if report.ok else EXIT_FAIL


def cmd_list(args) -> int:
    modules = helpers.get_modules()
    rows = []
    payload = []
    for namespace, definitions in sorted(modules.items()):
        for name, module in sorted(definitions.items()):
            rows.append(
                [
                    f"{namespace}/{name}",
                    module.risk,
                    "yes" if module.revertible else "NO",
                    ",".join(module.cis) or "-",
                    module.desc,
                ]
            )
            payload.append(module.to_dict())
    if args.get("json"):
        _print_json({"command": "list", "modules": payload, "count": len(payload)})
    else:
        print(render_table(["Module", "Risk", "Revert", "CIS", "Description"], rows))
        print(f"{len(payload)} modules available for {helpers.target_os_name()}.")
    return EXIT_OK


def cmd_history(args) -> int:
    limit = args.get("history") or 20
    journal = Journal()
    records = journal.history(limit)
    chain_ok, problems = journal.verify_chain()
    if args.get("json"):
        _print_json(
            {
                "command": "history",
                "journal": str(journal.path),
                "chain_ok": chain_ok,
                "chain_problems": problems,
                "records": [record.to_dict() for record in records],
            }
        )
        return EXIT_OK if chain_ok else EXIT_FAIL
    if not records:
        print(f"No journal entries in {journal.path} yet.")
        return EXIT_OK
    print(
        render_table(
            ["Run id", "When", "Module", "State"],
            [record.summary_row() for record in records],
            max_col_width=64,
        )
    )
    print(f"Journal: {journal.path}")
    if not chain_ok:
        for problem in problems:
            print(f"INTEGRITY: {problem}")
        return EXIT_FAIL
    print("Integrity: hash chain verified.")
    return EXIT_OK


def cmd_check(args) -> int:
    modules = _targets(args)
    journal = Journal()
    results = []
    failed = 0
    for module in modules:
        result = module.check()
        results.append(
            {
                "module": module.qualified_name,
                "compliant": result.ok,
                "exit_code": result.returncode,
                "output": result.summary(),
                "cis": list(module.cis),
                "risk": module.risk,
            }
        )
        if not result.ok:
            failed += 1
        if not args.get("json"):
            state = "COMPLIANT" if result.ok else "DRIFT    "
            print(f"[{state}] {module.qualified_name}: {result.summary(120)}")

    if not args.get("dry_run"):
        _record_audit(journal, args, results, failed)

    payload = {
        "command": "check",
        "ok": failed == 0,
        "summary": {
            "checked": len(results),
            "compliant": len(results) - failed,
            "drift": failed,
        },
        "results": results,
    }
    if args.get("json"):
        _print_json(payload)
    else:
        print(
            f"{len(results) - failed}/{len(results)} modules compliant, "
            f"{failed} require attention."
        )
    return EXIT_OK if failed == 0 else EXIT_FAIL


def _record_audit(journal, args, results, failed):
    """Store one compact audit record (evidence for compliance reviews)."""

    from graphenex.core.hrd.journal import new_run_id

    journal.append(
        RunRecord(
            run_id=new_run_id(),
            action="audit",
            module="<audit>",
            ok=failed == 0,
            returncode=0 if failed == 0 else 1,
            extra={
                "target": args.get("check"),
                "results": results,
                "compliant": len(results) - failed,
                "drift": failed,
            },
        )
    )


def cmd_apply(args) -> int:
    modules = _targets(args)
    if not modules:
        print("No modules matched the target.", file=sys.stderr)
        return EXIT_USAGE

    dry_run = bool(args.get("dry_run"))
    if not dry_run and not args.get("yes"):
        try:
            if not prompts.confirm(
                f"Apply {len(modules)} module(s) and record them in the journal?",
                default=False,
            ):
                print("Aborted.")
                return EXIT_OK
        except prompts.PromptError as exc:
            print(f"Aborted: {exc}", file=sys.stderr)
            return EXIT_USAGE

    journal = Journal()
    results = []
    failed = 0
    for module in modules:
        try:
            outcome = module.apply(
                dry_run=dry_run,
                journal=journal,
                force=bool(args.get("force")),
                allow_unrevertible=bool(args.get("allow_unrevertible")),
                allow_irreversible=bool(args.get("allow_irreversible")),
            )
        except (PermissionError, ValueError) as exc:
            failed += 1
            results.append({"module": module.qualified_name, "ok": False, "error": str(exc)})
            if not args.get("json"):
                print(f"[FAILED   ] {module.qualified_name}: {exc}")
            continue

        results.append(outcome.to_dict())
        if not outcome.ok:
            failed += 1
        if not args.get("json"):
            if outcome.already_compliant:
                print(f"[COMPLIANT] {module.qualified_name}: nothing to do")
                continue
            state = "APPLIED  " if outcome.ok else "FAILED   "
            verified = "" if outcome.verified is None else (
                " verified" if outcome.verified else " NOT verified"
            )
            print(f"[{state}] {module.qualified_name}: {outcome.result.summary(120)}{verified}")
            if outcome.run_id and outcome.journaled:
                print(f"            run id: {outcome.run_id}")
            if outcome.restart_required:
                print("            a restart is required for this change to take effect")

    payload = {
        "command": "apply",
        "ok": failed == 0,
        "dry_run": dry_run,
        "summary": {"total": len(results), "failed": failed},
        "results": results,
    }
    if args.get("json"):
        _print_json(payload)
    else:
        print(
            f"{len(results) - failed}/{len(results)} module(s) applied successfully."
            + (" (dry run)" if dry_run else "")
        )
        if failed == 0 and not dry_run:
            print("Undo with: grapheneX --revert last")
    return EXIT_OK if failed == 0 else EXIT_FAIL


def cmd_revert(args) -> int:
    journal = Journal()
    spec = args.get("revert") or "last"
    runs = resolve_runs(journal, spec)
    if not runs:
        message = f"nothing to revert for {spec!r}"
        if args.get("json"):
            _print_json({"command": "revert", "ok": True, "results": [], "message": message})
        else:
            print(message)
        return EXIT_OK

    dry_run = bool(args.get("dry_run"))
    if not dry_run and not args.get("yes") and len(runs) > 1:
        try:
            if not prompts.confirm(f"Revert {len(runs)} run(s)?", default=False):
                print("Aborted.")
                return EXIT_OK
        except prompts.PromptError as exc:
            print(f"Aborted: {exc}", file=sys.stderr)
            return EXIT_USAGE

    results = []
    failed = 0
    for record in runs:
        outcome = revert_record(record, journal=journal, dry_run=dry_run)
        results.append(outcome.to_dict())
        if not outcome.ok:
            failed += 1
        if not args.get("json"):
            state = "REVERTED " if outcome.ok else "FAILED   "
            print(f"[{state}] {record.module} ({record.run_id})")
            for item in outcome.restored:
                print(f"            {item['action']:<10} {item['path']}")
            if outcome.error:
                print(f"            error: {outcome.error}")
            for message in outcome.messages:
                print(f"            note: {message}")

    payload = {
        "command": "revert",
        "ok": failed == 0,
        "dry_run": dry_run,
        "summary": {"total": len(results), "failed": failed},
        "results": results,
    }
    if args.get("json"):
        _print_json(payload)
    else:
        print(
            f"{len(results) - failed}/{len(results)} run(s) reverted."
            + (" (dry run)" if dry_run else "")
        )
    return EXIT_OK if failed == 0 else EXIT_FAIL


def run(args) -> int:
    """Entry point for batch mode. Returns the process exit code."""

    try:
        return _run(args)
    except BatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _run(args) -> int:
    if args.get("validate"):
        return cmd_validate(args)
    if args.get("list"):
        return cmd_list(args)
    if args.get("history") is not None:
        return cmd_history(args)
    if args.get("check") is not None:
        return cmd_check(args)
    if args.get("apply") is not None:
        return cmd_apply(args)
    if args.get("revert") is not None:
        return cmd_revert(args)
    print("Nothing to do.", file=sys.stderr)
    return EXIT_USAGE


def is_batch(args) -> bool:
    """Return ``True`` when any batch-mode option was requested."""

    return any(
        [
            args.get("validate"),
            args.get("list"),
            args.get("history") is not None,
            args.get("check") is not None,
            args.get("apply") is not None,
            args.get("revert") is not None,
        ]
    )
