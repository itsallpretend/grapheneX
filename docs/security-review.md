# grapheneX security and compliance review

| | |
|---|---|
| Date | 2026-10-30 |
| Scope | `graphenex/` (CLI, web interface, module store), `modules.json`, packaging and container image |
| Version reviewed | 1.7.0 (`c8a8770`) and the 2.0.0 remediation on this branch |
| Method | Manual source review, threat modelling, dependency review, unit/integration tests, `graphenex --validate` gate |

This document records what was found, what was changed and what risk remains. It
is written to be usable as evidence in an internal audit: each finding has an
ID, a severity, the weakness class (CWE), the affected code and its status.

## 1. System model

grapheneX runs hardening commands on the local machine, normally as root or
Administrator. Inputs are (a) the operator's CLI input, (b) `modules.json`, and
(c) web requests from a browser authenticated with a single access token. The
security boundary that matters is therefore **the module store and the web
interface**: both can cause privileged command execution.

Threat model used for this review:

* remote, unauthenticated attacker able to reach the web port;
* authenticated but non-root web user;
* local unprivileged user able to influence environment variables or files;
* operator error (a module that breaks SSH, a command that hangs);
* supply chain (dependencies, module definitions).

## 2. Findings

| ID | Severity | CWE | Finding | Status |
|----|----------|-----|---------|--------|
| GX-001 | Critical | CWE-78 | Every module executed through a shell; module authoring reachable from the web UI | Fixed |
| GX-002 | High | CWE-306/614 | Web server bound to `0.0.0.0`, token over plaintext, weak cookie flags | Fixed |
| GX-003 | High | CWE-208/352 | Token compared with `!=`, no CSRF protection, no brute-force protection | Fixed |
| GX-004 | High | CWE-346/488 | Socket.IO accepted cross-origin connections; shared global namespace state | Fixed |
| GX-005 | High | CWE-94 | `add_module` persisted arbitrary commands without validation | Fixed |
| GX-006 | Medium | CWE-79 | DOM XSS through module names/descriptions/namespaces | Fixed |
| GX-007 | Medium | CWE-312/732 | Secret key written next to site-packages with default permissions | Fixed |
| GX-008 | Medium | CWE-778 | No audit trail, no rollback, no evidence of what changed | Fixed |
| GX-009 | Medium | CWE-1088/400 | Commands unbounded in time; stderr discarded; child processes leaked | Fixed |
| GX-010 | Medium | CWE-20 | `modules.json` not validated; malformed modules failed at runtime | Fixed |
| GX-011 | Low | CWE-693 | Missing security headers (CSP, frame-ancestors, nosniff) | Fixed |
| GX-012 | Low | CWE-117/532 | Logs mixed with output on stdout; ANSI colour always enabled | Fixed |
| GX-013 | Low | CWE-1104 | Unmaintained/EOL dependencies with known issues | Fixed |
| GX-014 | Low | CWE-250 | Documentation recommended `docker run --privileged` with no healthcheck | Mitigated |
| GX-015 | Info | CWE-1357 | No dependency or SAST gate in CI beyond CodeQL/Dependabot | Mitigated |
| GX-016 | Info | CWE-1059 | Module content is trusted code with no signature | Accepted |

### GX-001 - Shell injection and unauthenticated-adjacent code execution (Critical)

**Before.** `LinuxExec.run_cmd()` called `subprocess.run(cmd, shell=True)` for
every module, and `add_module` accepted any string from the browser and wrote it
to `modules.json`. Any web session (or anyone able to edit the JSON file) could
therefore execute arbitrary commands as root, and a module written for a
specific purpose could silently chain extra commands.

**After.**

* `graphenex/core/hrd/exec.py` no longer uses a shell unless the module declares
  `"shell": true`. Without that flag the command is parsed with `shlex` and
executed as an argument vector, so metacharacters are passed literally (test:
  `tests/test_exec.py::test_metacharacters_are_not_interpreted_without_shell`).
* The schema takes the decision explicitly and warns when metacharacters are
  present without `shell` (`tests/test_schema.py`).
* Web module authoring is disabled unless `GRAPHENEX_ALLOW_MODULE_AUTHORING=1`;
  submissions are normalised and validated before the file is written
  atomically.
* The journal stores a SHA-256 of every executed command, so a module file
  changed after a run is detectable.

**Why shell support remains.** Realistic hardening needs redirection, pipes and
`&&` (for example writing an sshd drop-in and validating it with `sshd -t` in
one atomic step). Removing shell support entirely would mean reimplementing a
shell in Python or splitting every module into fragile multi-step state
machines. The risk is controlled by making the choice explicit, reviewed and
visible in `grapheneX info` and `--list` output.

### GX-002 - Web exposure and session handling (High)

**Before.** The default listen address was `0.0.0.0`; the access token was shown
only in stdout; the session cookie lacked `SameSite`, `Secure` and an explicit
lifetime; there was no warning when the interface was reachable from the
network.

**After.** `DEFAULT_HOST` is `127.0.0.1` (containers set `GRAPHENEX_WEB_HOST=0.0.0.0`
explicitly). `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Strict"`,
`SESSION_COOKIE_SECURE` when `GRAPHENEX_HTTPS=1` (which also enables HSTS), an
eight-hour lifetime, `MAX_CONTENT_LENGTH` of 64 KiB, and a startup warning for
non-loopback binds. The token is printed to stderr only and is never written to
disk.

**Residual risk.** TLS termination is delegated to a reverse proxy; the built-in
server is still Werkzeug. This is documented in `SECURITY.md`.

### GX-003 - Authentication weaknesses (High)

**Before.** `token == app.config['ACCESS_TOKEN']`, no CSRF token on the login
form, unlimited attempts, session not cleared on login.

**After.** Constant-time `secrets.compare_digest`, a per-session CSRF token
validated before the token is read, rejection of malformed tokens, five failed
attempts per address per five minutes returning HTTP 429 with `Retry-After`,
`session.clear()` before granting the session, and the session marked permanent.
Log lines record the client address but never the token.

### GX-004 - Cross-origin WebSocket and shared state (High)

**Before.** `SocketIO(app)` used the default permissive CORS handling and
`current_namespace` was a module-level global, so two browser sessions shared
one namespace and any origin could connect with a victim's cookies.

**After.** `cors_allowed_origins=[]` (same-origin only), per-connection namespace
state keyed by Socket.IO session id, cleanup on `disconnect`, and payload type
validation for every event. `send_current_namespace` rejects unknown namespaces
instead of raising.

### GX-005 - Unvalidated module persistence from the browser (High)

**Before.** `add_module` built a dictionary from user input and appended it to
`modules.json`; only the module *name* was checked. A typo in the JSON could
break startup, and a malicious entry could persist root code execution across
restarts.

**After.** Authoring is opt-in; payloads are normalised through
`hrd.schema.normalize_module` (name, description, commands, files, timeout, risk,
control mappings) and written with `helpers.save_mod_json`, which validates the
whole file and writes it atomically with mode 0644. Rejected submissions return
the first concrete validation issue to the UI and to the log.

### GX-006 - DOM XSS (Medium)

The module list was rendered with string concatenation
(`'<h6>' + name + '</h6>'`), and namespaces used the same pattern. A crafted
`modules.json` could execute script in an authenticated session.

The UI now builds elements with jQuery DOM APIs and inserts every dynamic value
with `.text()` (`static/js/template.js`, `static/js/index.js`). A strict
`Content-Security-Policy` (`script-src 'self'`) provides defence in depth and the
inline `onclick` handler was removed.

### GX-007 - Secret key storage (Medium)

The Flask secret was written to the directory *above* the installed package
(`site-packages/../.env`), which is often read-only, may be world-readable and is
destroyed on upgrade. Secrets are now stored in
`$XDG_CONFIG_HOME/graphenex/.env` (fallback `~/.config/graphenex/.env`), created
with mode 0600 inside a 0700 directory, using an explicit `KEY=VALUE` parser
instead of an external dependency. A secret is generated only when the web
interface is started, not for CLI-only runs.

### GX-008 - No audit trail or rollback (Medium)

The framework could not answer "what changed, when, by whom, and how do I undo
it" - a blocker for any change-management control.

**After.** `graphenex/core/hrd/journal.py` implements an append-only, hash-chained
JSONL journal in `~/.local/state/graphenex/journal.jsonl` (0600). Each record
contains the run id, module, platform, OS user, elevation, both commands, the
command digest, exit status, duration, bounded stdout/stderr, pre-change probe
output, backup metadata and post-change hashes. Reverting records a second entry
linked by `parent_run_id`, so the journal shows both directions. The hash chain
makes silent edits or deletions detectable (`grapheneX --history` verifies it,
and there is a test that tampers with a record).

### GX-009 - Command execution robustness (Medium)

`subprocess.run(..., shell=True)` had no timeout, discarded stderr, raised on any
non-zero exit (so "already hardened" looked like a permission error) and replaced
`$USER` with `os.environ["USER"]` (a `KeyError` in cron/systemd environments).

**After.** Execution goes through a single `_spawn` helper with:

* a per-module timeout (1-3600 s) and process-group termination on expiry,
  including grandchildren;
* captured stdout/stderr, truncated at 64 KiB;
* structured `CommandResult` objects instead of exceptions;
* sanitised environment (`LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`, ... removed,
  `LC_ALL=C`);
* `$USER`/`$HOME` expansion only, never command substitution;
* a dry-run mode that never spawns a process.

### GX-010 - Module validation (Medium)

Any dictionary with a `command` key was accepted and only failed when executed.
`hrd/schema.py` now defines schema version 2 with fail-closed validation: name
and namespace patterns, mandatory audit command, mandatory revert definition
(or an explicit irreversible declaration with a reason), absolute non-traversal
file paths, timeout bounds, risk level, CIS/NIST patterns and unknown-field
warnings. `get_modules()` excludes invalid modules and emits an error, and
`grapheneX --validate` reports everything with exit code 1 so CI can gate on it.

### GX-011 to GX-013 - Response and dependency hygiene (Low)

* Security headers: `Content-Security-Policy` (no inline script, no framing),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Permissions-Policy`, `Cache-Control: no-store` for dynamic pages.
* Logging moved to stderr with automatic colour detection (`NO_COLOR`), so
  `--json` output on stdout stays parseable for SIEM/CI ingestion.
* Dependencies: removed PyInquirer (unmaintained, needed a `sed` patch on install),
  terminaltables, coloredlogs, colorama and python-dotenv; upgraded to Flask 3.x,
  flask-socketio 5.x and Python 3.11-3.13. The `sed` workarounds were deleted from
the Dockerfile and CI.

### GX-014 - Container guidance (Low, mitigated)

The README recommended `docker run --privileged`. The documentation now shows
`--cap-add=NET_ADMIN --cap-add=SYS_ADMIN`, mounts
`/root/.local/state/graphenex` as a volume, adds a healthcheck based on
`grapheneX --validate`, and notes that the container still runs as root because
hardening `/etc` and systemd requires it. Running unprivileged is not possible
for the privileged modules and is explicitly out of scope.

### GX-015 - CI security gates (Informational, mitigated)

CodeQL and Dependabot already existed. This change adds a unit-test job across
Python 3.11/3.12/3.13 and a `grapheneX --validate` gate to CI. Adding `bandit`
and `pip-audit` to CI is recommended and tracked in the repository backlog; both
tools are available in the `security` job described in
[CONTRIBUTING.md](../CONTRIBUTING.md).

### GX-016 - Module content is trusted code (Informational, accepted)

A module is executable configuration, like an Ansible task or a sudoers entry.
grapheneX does not sign modules and has no remote module registry. The controls
are: schema validation, review in version control, the hash of the executed
command in the journal, and the opt-in authoring gate. A signature scheme was
considered but would require key management that does not fit the project's
single-binary, offline-friendly design. This is an accepted risk, documented in
`SECURITY.md`.

## 3. Verification performed

```shell
python -m unittest discover -s tests -t . -v   # 86 tests, no third-party deps
python -m graphenex --validate                 # 84 modules, 8 presets, 0 errors
python -m graphenex --list --json              # machine-readable inventory
python -m graphenex --apply <target> --dry-run # no process is spawned
python -m graphenex --revert last              # restores backups and verifies
```

Test coverage of the security-relevant behaviour:

| Area | Test file |
|------|-----------|
| No implicit shell, metacharacters inert, timeouts, env sanitising | `tests/test_exec.py` |
| Schema validation, revert requirement, path traversal, shell warnings | `tests/test_schema.py` |
| Journal hash chain and tamper detection, 0600/0700 permissions, backup restore | `tests/test_journal.py` |
| Apply/revert round-trips, dry-run, irreversible refusal, revert without module definition | `tests/test_harden.py` |
| Shipped module library and presets (every module has audit + revert + control mapping) | `tests/test_modules.py` |
| Batch CLI exit codes and JSON output | `tests/test_cli.py` |

## 4. Residual risks and recommendations

1. **Single shared token, no RBAC.** Deploy behind an authenticating proxy if
   multiple operators need separate accounts, and correlate journal entries with
   the proxy logs.
2. **No built-in TLS.** Use a reverse proxy and set `GRAPHENEX_HTTPS=1`.
3. **Privileged process.** A compromised grapheneX process is equivalent to
   root. Restrict module authoring, keep the state directory private and run it
   on the host console or a management network.
4. **Module library coverage is indicative.** CIS/NIST identifiers map to the
   benchmark families the modules address, not to a specific benchmark version.
   Validate the mapping against your benchmark release before claiming
   compliance (see [compliance.md](compliance.md)).
5. **Windows modules need review per OS version.** Registry paths, DISM feature
   names and PowerShell cmdlets differ between Windows Server and client SKUs.
6. **Restart-dependent changes.** Applying and reverting a module that requires a
   restart leaves the running service in its previous state until restarted.
7. **Backup retention.** `Journal.prune_backups()` exists but is not scheduled;
   backups of sensitive files will accumulate in the state directory.

## 5. Change log for this review

| Change | Files |
|--------|-------|
| Safe executor with timeouts, process-group kill, structured results | `graphenex/core/hrd/exec.py` |
| Module schema v2 and validation | `graphenex/core/hrd/schema.py`, `graphenex/modules.json` |
| Journal, backups and hash chain | `graphenex/core/hrd/journal.py`, `graphenex/core/hrd/recovery.py` |
| Check/apply/revert engine | `graphenex/core/hrd/__init__.py` |
| Batch CLI, JSON output, prompts, tables | `graphenex/core/cli/`, `graphenex/__main__.py` |
| Web hardening, CSRF, lockout, CSP, safe DOM | `graphenex/core/web/` |
| Secrets and XDG paths | `graphenex/core/utils/paths.py`, `graphenex/core/utils/helpers.py` |
| Dependency modernisation and CI | `pyproject.toml`, `Dockerfile`, `.github/workflows/ci.yml` |
