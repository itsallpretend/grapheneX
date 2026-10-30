# Module schema v2 and authoring guide

A module is one hardening control: an **apply** command, an **audit** command
and a **revert** path. `modules.json` is validated on every load and by
`grapheneX --validate`; a module that fails validation is never executed.

## 1. Anatomy

```json
{
    "name": "SSH_Disable_Root_Login",
    "desc": "Forbid direct root logon over SSH.",
    "command": "install -d -m 0755 /etc/ssh/sshd_config.d && printf 'PermitRootLogin no\\n' > /etc/ssh/sshd_config.d/99-graphenex-ssh-disable-root-login.conf && sshd -t",
    "check": "sshd -T 2>/dev/null | grep -qi '^permitrootlogin no'",
    "revert": "sshd -t",
    "files": ["/etc/ssh/sshd_config.d/99-graphenex-ssh-disable-root-login.conf"],
    "shell": true,
    "timeout": 120,
    "require_superuser": true,
    "require_restart": true,
    "target_os": "linux",
    "risk": "medium",
    "cis": ["5.2.8"],
    "nist": ["AC-17"],
    "tags": ["ssh", "access"],
    "notes": "Make sure an administrative account with sudo exists first.",
    "probe": "systemctl is-active ssh 2>&1"
}
```

### Fields

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | `^[A-Za-z][A-Za-z0-9_]{2,63}$`, unique per namespace |
| `desc` | yes | One or two sentences, max 600 characters |
| `command` | yes | Applies the hardening change |
| `check` | yes | Audit; **exit code 0 means compliant** |
| `revert` | unless `files`/`irreversible` | Undoes the change |
| `files` | no | Absolute paths or globs snapshotted before apply and restored on revert |
| `shell` | no (default `false`) | Opt in to `/bin/sh` (or `cmd.exe`) semantics: pipes, redirects, `&&` |
| `timeout` | no (default 120) | Seconds, 1-3600; the process group is killed on expiry |
| `require_superuser` | no | Refuse to apply unless euid 0 / Administrator |
| `require_restart` | no | Remind the operator and record it in the journal |
| `target_os` | yes | `linux` or `win` |
| `risk` | no (default `medium`) | `low`, `medium`, `high`, `critical` (shown in the UI/CLI) |
| `cis` / `nist` | recommended | Control identifiers for reporting (`5.2.8`, `AC-17`) |
| `tags` | no | Free-form search tags |
| `notes` | no | Operator-facing caveats |
| `probe` | no | Read-only command whose output is recorded before the change so the operator knows the previous state |
| `irreversible` | no | `true` only when reverting is genuinely impossible; requires `irreversible_reason`; blocked unless `--allow-irreversible` |
| `idempotent` | no | Informational; `check` already provides idempotency |
| `requires` | no | Free-form dependency notes (not enforced) |

### Revert strategies

| Strategy | When to use | Behaviour |
|---|---|---|
| `command` | State lives outside files or is easy to invert | Runs `revert` |
| `files` | Configuration files | Restores content, mode, symlink target or deletes files that did not exist before; no `revert` command needed |
| `command+files` | Files plus a reload | Restores files first, then runs `revert` (for example `sysctl --system` or `sshd -t`) |
| none | Legacy 1.x modules | Refused unless `--allow-unrevertible`; use only to clean up |

`grapheneX info` and `--list` show the strategy (`Revert` column) for every
module.

## 2. Authoring rules

1. **Every module needs `check`.** If you cannot verify a setting, the module is
   not testable and cannot be audited or safely reverted.
2. **Prefer drop-in configuration files.** Write
   `/etc/<service>/conf.d/99-graphenex-<module>.conf` and list it in `files`.
   This is idempotent, avoids fragile `sed` edits of vendor files and makes
   revert a file restore.
3. **Validate before you commit a change.** Commands like `sshd -t`,
   `visudo -cf /etc/sudoers` and `sysctl --system` belong in the apply and
   revert command so a broken file is caught immediately.
4. **Never guess the previous state.** Use `probe` for state you cannot snapshot
   (service enablement, registry values, bootloader settings) and record it in
   the journal.
5. **Set `shell` deliberately.** Without it, metacharacters are inert. The
   validator warns when a command contains `|`, `>`, `&&`, `;`, backticks or `$(`
   while `shell` is false.
6. **Keep commands non-interactive.** `APT::Get::Assume-Yes`, `-y`, `--force`
   where appropriate; there is no TTY and stdin is `/dev/null`.
7. **Do not install packages.** A module that needs a tool should fail cleanly;
   installing software is a separate change with its own approval.
8. **Test both directions.** `grapheneX --apply <target> --dry-run`,
   `grapheneX --apply <target>`, `grapheneX --check <target>`, then
   `grapheneX --revert last` and check that the audit reports drift again.
9. **Map the control.** Add `cis` and `nist` so reports and the compliance table
   stay meaningful.
10. **Test files in CI** (`tests/test_modules.py`) enforce these invariants.

## 3. Authoring from the CLI

```shell
grapheneX
[gX]> manage
```

The `manage` flow asks for namespace, name, description, apply/audit/revert
commands, file snapshots, shell requirement, privileges, restart requirement and
risk level, validates the result and only then writes the file atomically.

Manual edits are fine too:

```shell
$EDITOR "$(python -c 'import graphenex.core.utils.paths as p; print(p.modules_file())')"
grapheneX --validate
```

Set `GRAPHENEX_MODULES=/path/to/modules.json` to work on an alternative file
(useful for staging a baseline before rolling it out).

## 4. Migration from 1.x

1.x had 77 modules, many of them one-liners that appended to vendor files with
`echo ... >>`, had no audit command and no way to undo anything. 2.0 replaces
them with 84 modules that bundle related settings into a single validated,
reversible control.

| 1.x modules | 2.x module(s) |
|---|---|
| `SSH_Disable_Root`, `SSH_Disable_Password_Login`, `SSH_Disable_Empty_Passwords` | `network/SSH_Disable_Root_Login`, `network/SSH_Disable_Password_Authentication`, `network/SSH_Disable_Unused_Features` |
| `SSH_Max_Auth_Tries`, `SSH_Login_Grace_Time` | `network/SSH_Session_Limits` |
| `SSH_Disable_X11_Forwarding`, `SSH_Disable_Agent_Forwarding`, `SSH_Disable_Tcp_Forwarding`, `SSH_Disable_Tunnel` | `network/SSH_Disable_Unused_Features` |
| `SSH_Disable_Protocol_1`, `SSH_Disable_Client_Legacy_Ciphers` | `network/SSH_Harden_Crypto` |
| `SSH_Disable_Client_*`, `SSH_Client_Key_Warn` | `network/SSH_Client_Strict_Host_Keys` |
| `SSH_Disable_Banner` | `other/Login_Legal_Banner` (inverted: now enables a banner) |
| `SSH_Change_Default_Port` | not shipped (`--port` breaks documented CIS baselines; use a firewall + drop-in) |
| `Logs_Restrict_Access`, `Pointers_Restrict_Access`, `Randomise_Memory`, `ExecShield_Protection` | `kernel/Kernel_Restrict_Dmesg`, `kernel/Kernel_Restrict_Kernel_Pointers`, `kernel/Kernel_Randomize_VA_Space` |
| `Disable_IP_Source_Routing`, `Disable_Redirect_Acceptance`, `Ignore_ICMP_IPv4`, `Force_SYN`, `Fragment_Drop`, `XMAS_Drop`, `Drop_Null`, `Ignore_Broadcast` | `network/Network_Ignore_ICMP_Redirects`, `network/Network_Enable_SYN_Cookies`, `network/Network_Enable_RP_Filter` |
| `Disable_IPv6_Systemwide` | `network/Network_Ignore_Router_Advertisements` (less destructive; disabling IPv6 outright is out of scope) |
| Windows `user/*`, `network/*`, `services/*` registry modules | `user/WIN_*`, `network/WIN_*`, `services/WIN_*`, `other/WIN_*` (same registry values, now with audit/revert) |

If you depend on a 1.x module that has no 2.x equivalent, add it with `manage`:
supply the audit and revert command (or `files`), and the validator will accept it.
Legacy modules imported as-is still load, but are marked `Revert: NO` and are
blocked from applying unless you pass `--allow-unrevertible`.
