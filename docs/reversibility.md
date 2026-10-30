# Reversibility: journal, backups and revert

Reverting is not a best-effort afterthought in grapheneX 2.0: a module that
cannot undo its change is rejected by the schema, and every apply records enough
information to be rolled back even if the module is later edited or deleted.

## 1. What happens during an apply

1. Refuse if the module requires root and the process is unprivileged.
2. Refuse if the module has no revert path (`revert` command, `files` snapshots
   or an explicit `irreversible` declaration).
3. Run the optional `probe` command and keep its output as the pre-change state.
4. Run the `check` command. If it already reports compliant, stop - nothing is
   changed and nothing is journaled unless `--force` is used.
5. Snapshot every `files` entry (glob-expanded) into
   `~/.local/state/graphenex/backups/<run-id>/`: content, mode and symlink
   target, plus a marker for paths that do not exist yet. With `--dry-run` the
   paths are only listed, nothing is written.
6. Run the apply command with a timeout.
7. Run `check` again and record whether the module is now compliant.
8. Append a hash-chained journal record with both commands, their digest, exit
   status, output, backups and post-change hashes.

## 2. What happens during a revert

1. Resolve the run: an explicit run id, `last` (newest pending), `all`, or a
   module target.
2. Refuse if the run is not an apply, or was already reverted (idempotent).
3. Restore every snapshot: rewrite content, reset mode, recreate symlinks and
   delete files/directories that did not exist before hardening.
4. Run the recorded `revert` command (typically a reload/validation such as
   `sysctl --system`, `sshd -t` or `systemctl daemon-reexec`).
5. Run the recorded audit command; the revert is *verified* when the module no
   longer reports compliant.
6. Append a `revert` journal record linked to the apply record via
   `parent_run_id`.

Restore happens **before** the revert command so that reload commands observe the
restored configuration.

## 3. Command line

```shell
grapheneX --revert                 # list pending runs (same as the `revert` command)
grapheneX --revert last            # newest pending run

grapheneX --revert 20261030T101500Z-1a2b3c4d
grapheneX --revert all --yes       # everything still applied
grapheneX --revert --dry-run       # show what would be restored
```

Inside the interactive shell the same operations are available with `revert`,
`revert last`, `revert all`, `revert <run-id>` and `history`.

## 4. The journal

`journal.jsonl` is append-only JSON Lines, mode 0600 in a 0700 directory. Each
line contains `prev` (the previous record's hash) and `hash` (SHA-256 over the
canonical record), so deleting or editing a line breaks the chain for every
following record. `grapheneX --history` and the web history panel verify the
chain automatically.

Example record (truncated):

```json
{
  "run_id": "20261030T101500Z-1a2b3c4d",
  "action": "apply",
  "module": "network/SSH_Disable_Root_Login",
  "target_os": "linux",
  "user": "root",
  "elevated": true,
  "command": "install -d ... && sshd -t",
  "command_sha256": "9f2c...",
  "returncode": 0,
  "ok": true,
  "pre_state": "active",
  "backups": [{"path": "/etc/ssh/sshd_config.d/99-graphenex-ssh-disable-root-login.conf", "existed": false, "kind": "missing"}],
  "extra": {"verified": true, "cis": ["5.2.8"], "post_hashes": {"/etc/ssh/sshd_config.d/99-...": "ab12..."}},
  "prev": "...",
  "hash": "..."
}
```

## 5. Failure modes and manual recovery

| Situation | What grapheneX does | What you should do |
|---|---|---|
| Apply command fails halfway | Keeps the backups and journals the failure | Inspect `--history`, then `--revert <run-id>` to clean up |
| Revert command fails | Reports which restore steps succeeded | Fix the underlying problem (for example a missing service) and retry; backups are retained |
| File changed by someone else after apply | Restores the backup anyway and reports `drifted` files | Review the drift warning; re-apply the change if the third-party edit was wanted |
| Module removed from `modules.json` | Revert still works from the journal | No action needed |
| Journal integrity check fails | `--history` exits non-zero and lists the broken records | Treat as a security incident; keep a copy before investigating |
| State directory deleted | Nothing can be reverted automatically | Re-apply the module with `--dry-run`/`--check` to reassess, or restore the directory from backup |

## 6. Retention

Backups live until you remove them. `Journal.prune_backups(keep=20)` deletes
backup directories for old, already-reverted runs (the newest `keep` runs are
preserved, and anything still pending is always kept).

```shell
python - <<'PY'
from graphenex.core.hrd.journal import Journal
print(Journal().prune_backups(keep=20), "backup directories removed")
PY
```

Backups can contain `/etc/shadow`, host keys and sudoers fragments: treat the
state directory as sensitive data (see `SECURITY.md`).
