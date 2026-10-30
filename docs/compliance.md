# Compliance mapping and evidence guide

> **Not a certification.** This document maps grapheneX capabilities to common
> control frameworks so that auditors can see which evidence the tool produces.
> It does not prove compliance: people, process, scope and the rest of the
> control environment still have to be in place. CIS/NIST identifiers in
> `modules.json` are *indicative* and must be verified against the benchmark
> version and platform you actually run.

## 1. What grapheneX contributes to a control environment

| Capability | Control intent | Evidence produced |
|---|---|---|
| Auditable baseline modules with `--check` | Configuration standards, secure baselines | JSON audit report, exit code, journal `audit` record |
| Explicit apply step with dry-run | Authorised change, change approval | `--apply --dry-run` output, run id |
| Automatic file backups before change | Recovery, integrity of configuration | Backup manifest in the journal with SHA-256 and modes |
| Mandatory revert path | Change management, rollback testing | `--revert` record linked to the apply record |
| Hash-chained journal | Audit logging, non-repudiation of changes | `journal.jsonl` with `prev`/`hash`, verified by `--history` |
| Machine-readable output | Continuous monitoring, CMDB / SIEM ingestion | `--json` on stdout, logs on stderr |
| Module validation gate | Configuration management, code review | `grapheneX --validate` exit code in CI |
| Security review | Risk assessment | `docs/security-review.md` |

## 2. Framework mapping

| grapheneX control | CIS Controls v8 | NIST SP 800-53 rev. 5 | ISO/IEC 27001:2022 | PCI DSS 4.0 | SOC 2 |
|---|---|---|---|---|---|
| Baseline modules (firewall, services, protocols) | 4.1, 4.2, 4.8 | CM-6, CM-7, SC-7 | A.8.9 | 1.2, 1.3, 2.2 | CC6.1, CC6.6 |
| Account and password policy modules | 4.1, 5.2 | AC-2, AC-7, IA-5 | A.5.15, A.5.17, A.8.5 | 8.2, 8.3, 8.5 | CC6.1, CC6.2 |
| Kernel / process hardening | 4.1 | CM-6, SI-16 | A.8.9 | 2.2 | CC6.1 |
| File permission modules | 3.3, 4.1 | AC-3, AC-6 | A.8.3, A.8.9 | 2.2, 7.1 | CC6.1 |
| Audit rules and logging modules | 8.1, 8.2, 8.5 | AU-2, AU-8, AU-12 | A.8.15, A.8.16 | 10.2, 10.4 | CC7.2, CC7.3 |
| Journal and `--history` integrity check | 8.1, 8.9 | AU-3, AU-9 | A.8.15 | 10.3, 10.5 | CC7.2 |
| Revert and backups | 11.4, 17.1 | CP-10, CM-3 | A.8.13, A.5.29 | 12.10 | A1.2, CC7.5 |
| Dry-run and validation gates | 4.1, 16.1 | CM-3, CM-4 | A.8.32 | 6.5 | CC8.1 |
| Web authentication, lockout, CSP | 5.1, 6.5 | AC-7, SC-8, SI-10 | A.8.5, A.8.20 | 6.4, 8.3 | CC6.1, CC6.6 |
| Module schema validation | 16.1 | SA-11, SI-10 | A.8.28 | 6.3 | CC8.1 |

## 3. Module coverage

Counts are generated from the shipped `modules.json` (schema v2). A namespace can
contain both Linux and Windows modules; `--list` shows what is available on the
current platform.

| Namespace | Linux | Windows | CIS controls referenced | Example controls |
|---|---|---|---|---|
| firewall | 3 | 5 | 7 | 3.5.1.1, 3.5.1.2, 3.5.2.1, 9.1, 9.2 |
| user | 8 | 7 | 14 | 1.1.1, 1.1.4, 1.2.2, 5.4.1, 5.5.1.1 |
| network | 13 | 6 | 28 | 3.1.1, 3.2.4, 3.2.7, 5.2.8, 5.2.11 |
| services | 7 | 5 | 12 | 1.2.1.1, 2.2.3, 4.1.1.1, 18.9.100.2 |
| kernel | 6 | 3 | 9 | 1.5.1, 1.5.4, 1.5.6, 1.5.7, 18.1.1 |
| filesystem | 5 | 3 | 11 | 1.1.1.1, 5.2.1, 6.1.2, 6.1.4, 18.8.13.1 |
| other | 7 | 6 | 12 | 4.1.3, 4.2.1.1, 5.2.19, 5.3.1, 18.9.4.1 |

Total: **84 modules** (Linux 49, Windows 35) and **8 presets** (`linux_baseline`,
`linux_ssh_server`, `linux_audit_ready`, `linux_workstation`,
`linux_hardened_server`, `windows_baseline`, `windows_server`,
`windows_workstation`).

## 4. Producing evidence

### 4.1 Audit the current state (no changes)

```shell
sudo grapheneX --check all --json > audit-$(date -u +%Y%m%dT%H%M%SZ).json
```

Exit code `0` means every selected module reported compliant; `1` means drift.
The same run appends an `audit` record with per-module results to the journal.

### 4.2 Apply a baseline with an approval trail

```shell
sudo grapheneX --apply linux_baseline --dry-run          # show the commands
sudo grapheneX --apply linux_baseline                     # interactive confirm
grapheneX --history 50 --json > change-record.json        # evidence
```

Every applied module gets a run id and a journal entry containing the command,
its SHA-256, exit status, output, pre-change probe and backups. A change ticket
can reference the run id.

### 4.3 Roll back

```shell
sudo grapheneX --revert <run-id>   # one change
sudo grapheneX --revert last       # most recent pending change
sudo grapheneX --revert all        # everything still applied
```

Reverts are verified with the module's own audit command and produce a linked
`revert` journal entry, which is exactly the "rollback tested" evidence change
management asks for.

### 4.4 Periodically verify the audit trail

```shell
sudo grapheneX --history 200 --json | jq '.chain_ok'
```

`false` means a journal line was modified or removed. Treat that as an incident:
the state directory is 0700, so only root should have been able to write to it.

## 5. Retention and protection

| Artefact | Location | Protection | Suggested retention |
|---|---|---|---|
| Journal | `~/.local/state/graphenex/journal.jsonl` | 0600, hash-chained | 1 year (or per policy) |
| Backups | `~/.local/state/graphenex/backups/<run-id>/` | 0700 directory, 0600 files | until the change is reverted + 30 days |
| Audit JSON | wherever you redirect stdout | your document management system | per audit cycle |
| Web access token | stderr of the web server | never persisted | session only |

Backups can contain secrets (`/etc/shadow`, host keys, sudoers). Encrypt the
state directory at rest or copy it into your encrypted evidence store; do not
email it or attach it to a ticket.

## 6. Gap analysis (what grapheneX does not do)

* **No continuous enforcement.** It applies and audits on demand; scheduling and
  drift detection belong to your configuration-management or SIEM tooling. Use
  `--check --json` from cron and alert on exit code `1`.
* **No vulnerability scanning.** Use a dedicated scanner; grapheneX hardens
  configuration, it does not detect missing patches.
* **No identity/RBAC.** One token, one operator. Correlate with proxy or PAM logs.
* **No evidence signing.** The hash chain detects tampering but is not a digital
  signature; export the journal to WORM storage if non-repudiation is required.
* **No automatic benchmark scoring.** CIS identifiers are metadata for
  traceability, not a scored assessment.
* **No remediation of reboot-only settings.** Modules record `require_restart`
  and remind the operator, but scheduling reboots is out of scope.
