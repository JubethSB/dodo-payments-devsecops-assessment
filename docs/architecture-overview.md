# Architecture Overview

How the four tasks fit together on one local k3d cluster. Each task's README has
its own detailed diagram; this is the system view and the trust boundaries that
span tasks.

## The whole system

```
  DEVELOPER / CI                         CLUSTER (k3d "ledger")
  ─────────────                          ──────────────────────────────────────

  git push
     │
     ▼
  ┌──────────────────────────┐  Task 2: pipeline holds NO cluster creds
  │ GitHub Actions (ci-cd)   │
  │  gitleaks ─ semgrep ─────┤  gates: secrets, SAST, dependency CVE, image CVE
  │  trivy fs ─ build ───────┤  build → GHCR
  │  trivy image ─ cosign ───┤  keyless sign + SPDX SBOM attestation (Fulcio/Rekor)
  │  update-gitops (commit)  │
  └───────────┬──────────────┘
              │ commits signed digest to gitops/ path
              ▼
  ┌──────────────────────────┐  pull, not push
  │ ArgoCD  (source of truth)│──────────────┐
  └──────────────────────────┘              │ reconciles + self-heals drift
                                             ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ namespace: payments      pci-scope=cde     PSS: restricted (enforce)     │
  │                                                                          │
  │  Admission (every pod CREATE):                                           │
  │    API server → PSS restricted → Kyverno (non-root, no :latest, signed)  │  Task 1
  │                                                                          │
  │  ┌───────────────── Istio mesh (mTLS STRICT) ─────────────────────────┐  │
  │  │                                                                     │  │  Task 3
  │  │   Ingress Gateway ──TLS term──▶ VirtualService (90/10 canary)       │  │
  │  │                                     │                               │  │
  │  │   reporting ───mTLS + SPIFFE authz──▶ ledger-api  (uid 10001,       │  │
  │  │        (SA: reporting)   200 OK          read-only rootfs, caps      │  │
  │  │                                          dropped, no SA token)       │  │
  │  │   unauthorised-client ──mTLS──✗ 403 rbac_access_denied              │  │
  │  │        (SA: unauthorised-client)                                    │  │
  │  └─────────────────────────────────────────────────────────────────────┘ │
  │                                                                          │
  │  NetworkPolicy: default-deny ingress+egress, explicit allows (L3/L4)     │  Task 3
  │  Secret ledger-api-secrets ◀── SealedSecrets controller ◀── ciphertext   │  Task 1
  └────────────────────────────────────────────────────────────────────────┘

  Task 4: same app.py, run locally as an AUTHORISED target, attacked from the
  outside (YAML-RCE, SSRF, PAN exposure, weak tokenization) — then mapped back
  to the controls above that blunt each finding.
```

## Trust boundaries, and which task owns each

| Boundary | Control | Task | What it stops |
|---|---|---|---|
| Registry → cluster | Kyverno `verify-image-signature` + cosign | 1 + 2 | Unsigned / tampered images running |
| API server → etcd | PSS `restricted` + Kyverno at admission | 1 | Root, `:latest`, privileged, missing hardening |
| git → cluster | ArgoCD pull model (CI has no kubeconfig) | 2 | A compromised runner mutating production |
| Secret at rest in git | SealedSecrets (key never leaves cluster) | 1 | Plaintext credential in a public repo |
| Pod ↔ pod (L7 identity) | Istio mTLS STRICT + AuthorizationPolicy on SPIFFE ID | 3 | An in-namespace workload calling a service it shouldn't |
| Pod ↔ pod (L3/L4) | Kubernetes NetworkPolicy default-deny | 3 | Traffic that never reaches a sidecar (unmeshed pod, bypassed proxy) |
| Mesh edge → CDE | Ingress Gateway TLS termination; ledger-api not exposed | 3 | The PCI-scoped service sitting on the edge |

## Why two layers of almost everything

The recurring theme, and the thing Task 4's retest section makes concrete: no
single control is trusted alone.

- **PSS *and* Kyverno** — PSS lives in the API server and survives someone
  deleting the Kyverno webhook; Kyverno expresses rules PSS cannot (registry,
  `:latest`, signature).
- **AuthorizationPolicy *and* NetworkPolicy** — the mesh policy is identity-aware
  but enforced by the sidecar; the NetworkPolicy is identity-blind but enforced
  by the CNI, so it still applies to a pod that never got a sidecar or whose
  proxy was bypassed.
- **Sign *and* verify** — the pipeline signs; Kyverno at admission is the
  consumer that refuses anything unsigned.

Task 4 finding → control mapping lives in
[`../task-4-recon-pentest/pentest-report.md`](../task-4-recon-pentest/pentest-report.md).
