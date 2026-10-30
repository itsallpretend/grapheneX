# Security policy

## Supported versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 2.x     | Yes       | Audited, reversible module schema (v2), Python 3.11+ |
| 1.x     | No        | End of life: unmaintained prompt/table dependencies, Flask 2.0, no revert support |

Version 1.7.0 is the last release of the 1.x series. If you are still running it,
upgrade before hardening production systems: 1.x cannot undo the changes it makes
and accepts arbitrary module commands without validation.

## Reporting a vulnerability

Please **do not open a public issue**. Report vulnerabilities privately to
`graphenex.project@protonmail.com` (or use GitHub's private vulnerability
reporting) with:

* affected version and platform;
* a description of the impact (what an attacker gains);
* reproduction steps or a proof of concept;
* whether the issue also affects `modules.json` content or the web interface.

We aim to acknowledge reports within five working days and to publish a fix and
advisory within 90 days. Credit is given unless you ask otherwise.

## Security model

Understanding what grapheneX can do is the first step to running it safely.

1. **Hardening modules are executable code.** A module in `modules.json`
   contains shell commands that grapheneX runs with the privileges of the
   process. Treat module definitions with the same care as `sudoers` or a
   provisioning playbook: review changes, keep them in version control and
   restrict who can edit them.
2. **grapheneX is usually run as root.** Most modules change `/etc`, systemd
   units or firewall state. Run it only on hosts you administer, and prefer the
   CLI on the local console over a browser session on a shared network.
3. **The web interface is a privileged remote control.** It is protected by a
   single access token printed on startup, CSRF protection, a login lockout,
   same-origin Socket.IO and a restrictive Content-Security-Policy. It binds to
   `127.0.0.1` by default. If you expose it, terminate TLS in front of it and
   restrict access to a management network.
4. **Every change is journaled and reversible.** Backups are written to the
   state directory (`~/.local/state/graphenex`, mode 0700) before a command
   runs, and each apply/revert is appended to a hash-chained journal. Review
   `grapheneX --history` after a run, and use `grapheneX --revert last` to undo.
5. **The state directory contains sensitive data.** Backups can include
   `/etc/shadow`, SSH host keys and sudoers fragments. Protect the directory,
   include it in your backup/retention policy and delete it securely when it is
   no longer needed.

## Hardening grapheneX itself

* Set `GRAPHENEX_ALLOW_MODULE_AUTHORING=1` only on workstations where you want
  to edit modules from the browser. It is disabled by default.
* Set `GRAPHENEX_WEB_HOST=127.0.0.1` (the default) and put a TLS reverse proxy
  in front of the web interface if remote access is required; also set
  `GRAPHENEX_HTTPS=1` so the session cookie is marked `Secure` and HSTS is sent.
* Use `--state-dir` on a filesystem with restrictive permissions and include it
  in your encrypted backups.
* Run `grapheneX --validate` after any edit of `modules.json`. Productions
  deployments should run it in CI; the test suite in `tests/test_modules.py`
  enforces the same invariants.
* Prefer `docker run --cap-add=NET_ADMIN --cap-add=SYS_ADMIN` over
  `--privileged`, and mount the state directory as a volume so the journal
  survives container restarts.

## Known limitations

* There is a single access token and no per-user roles or audit attribution
  beyond the operating-system user and remote address.
* `files` snapshots cover the paths (and glob matches) listed by the module at
  apply time. Files created later by other tools are not tracked.
* Modules that require a restart only revert the configuration; the running
  service keeps the hardened state until you restart it again.
* Windows modules rely on `cmd.exe`, PowerShell and `reg.exe` being available.
* grapheneX does not install missing tools. A module whose command is not
  present fails cleanly (exit code captured in the journal) without changing the
  system.

See [docs/security-review.md](docs/security-review.md) for the full review,
findings and residual risks, and [docs/compliance.md](docs/compliance.md) for the
control mapping.
