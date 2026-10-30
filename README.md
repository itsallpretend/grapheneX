![grapheneX](https://socialify.git.ci/grapheneX/grapheneX/image?description=1&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Fraw.githubusercontent.com%2FgrapheneX%2FgrapheneX%2Fmaster%2Fgraphenex%2Fcore%2Fweb%2Fstatic%2Fimages%2Fgraphenex_logo_white.png&owner=1&pulls=1&stargazers=1&theme=Dark)

# grapheneX [![Release](https://img.shields.io/github/release/grapheneX/grapheneX.svg?style=flat-square)](https://github.com/grapheneX/grapheneX/releases) [![License](https://img.shields.io/github/license/grapheneX/grapheneX.svg?style=flat-square)](./LICENSE) [![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff) [![Tests](https://img.shields.io/badge/tests-85%20passing-brightgreen.svg?style=flat-square)](#development--tests)

> In computing, hardening is usually the process of securing a system by reducing its surface of vulnerability, which is larger when a system performs more functions; in principle a single-function system is more secure than a multipurpose one. Reducing available ways of attack typically includes changing default passwords, the removal of unnecessary software, unnecessary usernames or logins, and the disabling or removal of unnecessary services.

`grapheneX` is an automated system hardening framework for Linux and Windows.
Every module answers three questions: **is this system compliant** (`--check`),
**how do I fix it** (`--apply`) and **how do I undo it** (`--revert`).

```shell
$ sudo grapheneX --check linux_baseline      # audit only, exit 1 on drift
$ sudo grapheneX --apply linux_baseline      # apply, with backups + journal
$ sudo grapheneX --revert last               # restore exactly what changed
```

## Why grapheneX 2.0

* **Reversible by design.** A module that cannot undo its change is rejected by
  the schema. File snapshots, a hash-chained journal and a verified revert path
  are part of the framework, not a per-module courtesy.
* **Auditable.** `--check` and `--json` produce machine-readable evidence for
  change management and compliance reviews.
* **Realistic baseline.** 84 modules across firewall, user, network, services,
  kernel, filesystem and audit controls, mapped to CIS and NIST 800-53
  identifiers - not one-liners that append to vendor files.
* **Safer by default.** No implicit shell, command timeouts, sanitised
  environment, loopback-only web server, CSRF, login lockout, CSP and safe DOM
  rendering.
* **Accessible.** Plain line-based prompts that work over serial consoles and
  with screen readers, `NO_COLOR`, no animation when the OS asks for reduced
  motion, keyboard-visible focus, labelled controls and a scriptable CLI that
  needs no TTY.

See [docs/security-review.md](docs/security-review.md) for the full review,
[docs/reversibility.md](docs/reversibility.md) for how rollback works and
[docs/compliance.md](docs/compliance.md) for the control mapping.

## Requirements

* Python 3.11, 3.12 or 3.13
* Linux or Windows
* Root / Administrator for modules that change system state

## Installation

```shell
pip install graphenex
# or
python3 -m pip install graphenex
```

With [poetry](https://python-poetry.org/) for development:

```shell
poetry install        # resolves and writes poetry.lock
poetry run grapheneX
```

### Docker

```shell
docker pull ghcr.io/graphenex/graphenex

docker run -it --rm -p 8080:8080 \
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  -v graphenex-state:/root/.local/state/graphenex \
  ghcr.io/graphenex/graphenex
```

Prefer `--cap-add` over `--privileged`, and always mount the state volume: it
holds the journal and the backups that make reverts possible. The image sets
`GRAPHENEX_WEB_HOST=0.0.0.0` for container networking; the CLI still defaults to
`127.0.0.1`.

Build locally:

```shell
docker build -t graphenex .
docker run -it --rm -p 8080:8080 --cap-add=NET_ADMIN --cap-add=SYS_ADMIN graphenex
```

## Usage

### Non-interactive (batch) mode

Designed for scripts, cron and pipelines: no prompts, stable exit codes
(`0` ok, `1` drift/failure, `2` usage error), JSON on stdout and logs on stderr.

```shell
grapheneX --list                                  # inventory for this OS
grapheneX --list --json                           # same, machine readable
grapheneX --validate                              # validate modules.json
grapheneX --check all                             # audit everything
grapheneX --check network/SSH_Harden_Crypto --json
grapheneX --apply linux_baseline --dry-run        # show commands, change nothing
grapheneX --apply linux_baseline --yes            # unattended (journaled)
grapheneX --revert last                           # undo the newest change
grapheneX --history 50 --json                     # audit trail + chain check
```

Targets are `all`, a namespace (`network`) or `namespace/Module_Name`
(`network/SSH_Harden_Crypto`). Presets (`--apply linux_ssh_server`) expand to a
list of modules.

Useful flags: `--dry-run`, `--force` (apply even when already compliant),
`--yes`, `--json`, `--no-color`, `--quiet`, `--state-dir DIR`,
`--modules FILE`, `--allow-unrevertible`, `--allow-irreversible`.

### Interactive shell

```shell
grapheneX
```

```
[gX]> list
[gX]> use network/SSH_Disable_Root_Login
[gX:network:SSH_Disable_Root_Login]> info
[gX:network:SSH_Disable_Root_Login]> check
[gX:network:SSH_Disable_Root_Login]> harden
[gX:network:SSH_Disable_Root_Login]> revert last
```

| Command | Description |
|---|---|
| `audit [target]` | Audit the current namespace or a target |
| `back` | Go back from a module or namespace |
| `check [target]` | Run the audit command (exit 0 = compliant) |
| `clear` | Clear the terminal |
| `exit` | Exit the shell |
| `harden` | Apply the selected module (backs up first) |
| `help [command]` | Command help |
| `history [N]` | Recent journal entries and integrity check |
| `info` | Module details: commands, risk, controls, revert strategy |
| `list` | Modules in the current namespace |
| `manage` | Add, edit or remove a module (validated) |
| `preset [preset]` | List or run a preset |
| `revert [last\|all\|RUN_ID\|MODULE]` | Revert applied changes |
| `search [query]` | Search names, descriptions and tags |
| `switch [namespace]` | Switch namespace |
| `use [namespace/Module]` | Select a module |
| `web [host:port]` | Start the web interface |

### Presets

Presets bundle modules into a profile. The shipped profiles are
`linux_baseline`, `linux_ssh_server`, `linux_audit_ready`, `linux_workstation`,
`linux_hardened_server`, `windows_baseline`, `windows_server` and
`windows_workstation`; each has a description and a risk level.

```shell
grapheneX --check linux_hardened_server --json
sudo grapheneX --apply linux_ssh_server
```

Presets live in `modules.json`:

```json
{
    "name": "linux_ssh_server",
    "desc": "SSH server hardening...",
    "risk": "high",
    "target_os": "linux",
    "modules": ["network/SSH_Disable_Root_Login", "network/SSH_Harden_Crypto"]
}
```

`namespace/All` means every module in that namespace.

### Web interface

```shell
grapheneX --web                 # http://127.0.0.1:8080
grapheneX --web 192.168.1.36:8090 --open
grapheneX -w --flask-secret-key <secure_key_here>
```

The access token is printed once on startup. The interface can run privileged
commands, so it binds to loopback by default; if you expose it, terminate TLS in
front of it and set `GRAPHENEX_HTTPS=1` so the session cookie is `Secure` and
HSTS is sent. Module authoring in the browser is disabled unless
`GRAPHENEX_ALLOW_MODULE_AUTHORING=1`.

The web UI supports check, run and revert per module and shows the journal with
an integrity indicator. It is keyboard navigable, has a skip link, visible focus,
`aria-live` announcements, labelled controls and honours
`prefers-reduced-motion`.

## Modules

A module declares an apply command, an audit command and a revert path:

```json
{
    "name": "SSH_Session_Limits",
    "desc": "Limit authentication attempts, sessions and idle time.",
    "command": "printf 'MaxAuthTries 4\\n...' > /etc/ssh/sshd_config.d/99-graphenex-...conf && sshd -t",
    "check": "sshd -T 2>/dev/null | grep -qi '^maxauthtries 4'",
    "revert": "sshd -t",
    "files": ["/etc/ssh/sshd_config.d/99-graphenex-ssh-session-limits.conf"],
    "shell": true,
    "require_superuser": true,
    "require_restart": true,
    "target_os": "linux",
    "risk": "low",
    "cis": ["5.2.5", "5.2.14"],
    "nist": ["AC-17"]
}
```

`grapheneX --validate` checks every module (name, audit and revert requirement,
absolute paths, timeout bounds, control identifiers, shell consistency) and
exits non-zero on the first problem. See [docs/modules.md](docs/modules.md) for
the full schema, authoring rules and the 1.x migration table.

Add modules from the CLI with `manage`, or edit
`$(python -c 'import graphenex.core.utils.paths as p; print(p.modules_file())')`
and re-run `grapheneX --validate`.

## State, journal and revert

| Path | Content |
|---|---|
| `~/.local/state/graphenex/journal.jsonl` | Hash-chained apply/audit/revert records (0600) |
| `~/.local/state/graphenex/backups/<run-id>/` | File snapshots taken before apply (0600, 0700 dir) |
| `~/.config/graphenex/.env` | Flask secret key (0600, only for the web UI) |

Override locations with `--state-dir` or `GRAPHENEX_STATE_DIR` /
`GRAPHENEX_CONFIG_DIR`. Every apply prints a run id, and `--history` verifies the
hash chain. Backups may contain secrets such as `/etc/shadow`; protect the state
directory and delete it securely when no longer needed.

## Development & tests

The hardening engine and the test suite use only the standard library:

```shell
python -m unittest discover -s tests -t . -v   # 85 tests
python -m graphenex --validate                 # 84 modules, 0 errors
python -m graphenex --list --json
```

Test layout:

| File | Scope |
|---|---|
| `tests/test_exec.py` | Safe execution, timeouts, shell opt-in, environment |
| `tests/test_schema.py` | Module schema and validation rules |
| `tests/test_journal.py` | Journal hash chain, permissions, backup/restore |
| `tests/test_harden.py` | Check/apply/revert round-trips, dry-run, refusals |
| `tests/test_modules.py` | Shipped module library and presets |
| `tests/test_cli.py` | Batch CLI exit codes and JSON output |

CI runs the tests on Python 3.11-3.13, validates `modules.json`, runs Ruff,
Bandit, pip-audit, CodeQL and builds the Docker image.

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
The 1.x series is end of life: it has no revert support, accepts unvalidated
module commands and depends on unmaintained packages.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). New modules must include `check`,
`revert` (or `files`), control identifiers and a passing `grapheneX --validate`.

## License

[GNU General Public License v3.0](./LICENSE)

## Sponsors

We don't have any sponsors yet. Contact us with email if you want to help us
improve the project.
