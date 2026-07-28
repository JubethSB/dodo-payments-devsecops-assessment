# Upstream provenance

This directory is an **unmodified** copy of the assignment's starter service.

| | |
|---|---|
| Source | https://github.com/bhabani-dodo/ledger-api-assignment.git |
| Commit | `2e1cd43fab5b9769d3bf506184db83627acae672` |
| Commit date | 2026-07-08 11:23:19 +0530 |
| Subject | `ledger-api service` |
| Retrieved | 2026-07-28 |

The nested `.git` directory was removed so these files commit as ordinary
content in the assessment repository rather than as a broken submodule
reference. Re-clone with:

```bash
git clone https://github.com/bhabani-dodo/ledger-api-assignment.git app-source
```

## Why nothing here is edited

These files are the **insecure baseline**. They serve two purposes and are
therefore left byte-for-byte as delivered:

1. `deploy/deployment.yaml` is applied in Task 1 to demonstrate the admission
   guardrails rejecting it (`evidence/01-...`). If it were fixed in place there
   would be nothing to reject.
2. `app/app.py` contains the application vulnerabilities — `yaml.load` on
   `/import`, SSRF on `/fetch`, cleartext PANs on `/transactions` — that are the
   authorised target for Task 4's penetration test.

The hardened equivalents live one directory up:

| Insecure original | Hardened replacement |
|---|---|
| `app/Dockerfile` | `../app-image/Dockerfile` |
| `deploy/deployment.yaml` | `../manifests/base/20-ledger-api-deployment.yaml` |
| `deploy/service.yaml` | `../manifests/base/30-ledger-api-service.yaml` |
| `deploy/namespace.yaml` | `../manifests/base/00-namespace.yaml` |
| `deploy/neighbour.yaml` | `../manifests/base/40-reporting.yaml` |

> **Note:** `deploy/deployment.yaml` contains a plaintext `sk_live_…` key and a
> database password. They are retained deliberately as the "before" state that
> Task 1 remediates. Both are fake assignment values, and the remediation
> (see the Task 1 README, §1.4) is rotation at the provider — not re-encryption.
