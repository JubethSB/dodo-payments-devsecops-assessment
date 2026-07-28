# Task 1 — Deploy & Harden the Workload

Takes `ledger-api` from the deliberately-insecure starter to a production-grade,
PCI-defensible deployment on a local Kubernetes cluster, and **proves** each
control is enforced rather than merely declared.

**Result: 17/17 automated verification checks pass** (`./scripts/verify.sh`).

---

## 1. Approach & design decisions

### 1.1 What was wrong with the starter

Reading `app-source/` first, before changing anything:

| # | Finding | Evidence in starter | Severity |
|---|---|---|---|
| 1 | Live-format Stripe key and DB password in plaintext in git | `deploy/deployment.yaml` `env:` block | **Critical** |
| 2 | Container runs as root | `app/Dockerfile` has no `USER`; no `securityContext` | **High** |
| 3 | Writable root filesystem | no `readOnlyRootFilesystem` | High |
| 4 | All default Linux capabilities retained | no `capabilities.drop` | High |
| 5 | seccomp unconfined | no `seccompProfile` | High |
| 6 | No resource requests/limits → BestEffort QoS, node-level DoS | Deployment | Medium |
| 7 | No liveness/readiness/startup probes | Deployment | Medium |
| 8 | Uses the shared `default` ServiceAccount, token auto-mounted | no `serviceAccountName` | Medium |
| 9 | No admission guardrails — nothing stops the next bad manifest | cluster-wide | High |
| 10 | Neighbour is a bare `curl … sleep infinity` shell with no purpose | `deploy/neighbour.yaml` | Medium |
| 11 | EOL base image (`python:3.6-slim`) and 2018-era dependencies | `app/Dockerfile`, `requirements.txt` | High |

### 1.2 Scope decision: what I deliberately did **not** fix

`app.py` contains three application-level vulnerabilities:

- `/import` → `yaml.load(request.data)` with no `SafeLoader` → **RCE via deserialisation**
- `/fetch?url=` → **SSRF**, unrestricted outbound fetch
- `/transactions` → returns **full PANs in cleartext**

**These are left intact on purpose.** They are the authorised target for Task 4's
penetration test; patching them here would delete the thing the pen test exists
to find. Task 1's remit is the *workload and platform*, and the hardening below
is specifically designed to **contain** these bugs rather than remove them —
which is the more honest security posture anyway, since you rarely get to
assume the app is bug-free.

The containment argument, concretely: an attacker who achieves RCE through
`/import` lands as **uid 10001, not root**, on a **read-only filesystem** (no
webshell, no miner, no persistence), with **all capabilities dropped** (no
`NET_RAW` for ARP spoofing), under **seccomp RuntimeDefault** (most escape
syscalls unavailable), and with **no ServiceAccount token** to pivot to the API
server. Task 4 maps each finding back to the control that blunts it.

### 1.3 Neighbour service — why `reporting` was rewritten

The task requires a neighbour with Deployment, Service and ConfigMap. The
starter's `reporting` was a `curl` container sleeping forever — no Service, no
config, and functionally just a shell sitting inside the PCI namespace.

I replaced it with a real service that calls `ledger-api` and serves an
aggregated `/summary`. It receives identical hardening, and it demonstrates
**data minimisation**: `ledger-api` exposes full PANs, but `reporting`
aggregates by currency/status and propagates **no `pan` field at all**
(verified by check 10). That keeps `reporting` outside PCI CDE scope — the
boundary Task 3 draws with the mesh.

The bare curl client returns in **Task 3** as the *unauthorised* caller used to
demonstrate `AuthorizationPolicy` denying traffic.

### 1.4 Secrets — Sealed Secrets, and why

Chosen over SOPS+age and External Secrets:

- **vs SOPS+age** — SOPS needs a private key distributed to every operator and
  to CI. Sealed Secrets encrypts to a controller keypair that *never leaves the
  cluster*; a developer needs only the public cert to seal. Fewer key copies,
  fewer ways to leak one.
- **vs External Secrets** — ESO is the better answer at scale, but it needs an
  external backend (Vault/ASM). The assessment must run fully local and free.
- **GitOps-native** — the encrypted `SealedSecret` is a normal manifest, so it
  commits cleanly and flows through the Task 2 ArgoCD pipeline unchanged.

**The plaintext key is gone.** Only ciphertext is committed
(`manifests/secrets/ledger-api-sealedsecret.yaml`), and check 7 fails the build
if either leaked literal reappears anywhere under `manifests/`.

**Credential rotation, not re-encryption.** The starter's `sk_live_…` was in git
history, so it is burned. `seal-secret.sh` seals a *placeholder* and documents
that the real remediation is rotating at Stripe — re-encrypting a public value
would be security theatre.

### 1.5 Two policy engines, deliberately

Both PSS `restricted` **and** Kyverno are enforced, because they fail
differently:

| | Pod Security Standards | Kyverno |
|---|---|---|
| Where it runs | Compiled into the API server | External admission webhook |
| Survives webhook deletion | **Yes** | No |
| Registry allow-lists, `:latest`, signatures | **Cannot express** | **Yes** |
| Resource limits | **Does not check** | **Yes** |
| Message quality | Generic | Names the exact failing rule |

Check 8 proves the split empirically: a root container is caught by **PSS**,
while `:latest`, missing limits and a writable rootfs are caught by **Kyverno**
on pods that PSS accepts. Delete either layer and real violations get through.

### 1.6 RBAC — the two decisions worth defending

**`ledger-api` gets a dedicated SA with *no* Role and *no* token.** The source
makes zero Kubernetes API calls, so least privilege is genuinely *nothing*.
Granting a token "just in case" hands an attacker with RCE a credential to
pivot with. Verified: `auth can-i --list` returns only the self-review verbs
every identity has, and the token path does not exist in the pod.

**No persona — including `admin` — can read core Secrets or exec into a pod.**
Sealing secrets in git is pointless if any developer can `kubectl get secret -o
yaml` the decrypted value. Admins manage **SealedSecrets** (ciphertext) instead.
`pods/exec` is treated as privileged, not a convenience: a shell runs with the
pod's identity and reads every mounted Secret, bypassing the Secret rules
entirely. Exec lives in a separate `payments-breakglass-exec` Role that is
**bound to nobody** — granting it is a discrete, auditable incident action.

> **Verification gotcha:** `kubectl auth can-i create pods/exec` (slash form)
> reports a false `yes` — it matches the plain `pods` grant. The authoritative
> form is `--subresource=exec`. Both are shown in
> `evidence/03-rbac-least-privilege.txt`.

---

## 2. Architecture

```
                    Internet / operator laptop
                              │
                    :8080 ──▶ ingress-nginx  (TLS, ssl-redirect,
                              │               nosniff / DENY / no-referrer)
   ┌──────────────────────────┼──────────────────────────────────────┐
   │  namespace: payments     │   PSS restricted (enforce/audit/warn)│
   │                          │   label pci-scope=cde                │
   │                          ▼                                      │
   │              ┌───────────────────────┐                          │
   │              │ Service ledger-api    │  ClusterIP :8080         │
   │              └───────────┬───────────┘                          │
   │                          ▼                                      │
   │        ┌─────────────────────────────────┐                      │
   │        │ Deployment ledger-api  (x2)     │   ◀── SealedSecret    │
   │        │  uid 10001 · RO rootfs          │       (ciphertext     │
   │        │  caps drop ALL · seccomp RD     │        in git)        │
   │        │  no SA token · limits + probes  │   ◀── ConfigMap       │
   │        └─────────────────────────────────┘                      │
   │                          ▲                                      │
   │                          │ http://ledger-api:8080               │
   │        ┌─────────────────┴───────────────┐                      │
   │        │ Deployment reporting  (x1)      │   ◀── ConfigMap       │
   │        │  uid 10002 · same hardening     │       (no secrets)    │
   │        │  /summary — aggregates, NO PANs │                      │
   │        └─────────────────────────────────┘                      │
   │                 (Service reporting, ClusterIP :8081,            │
   │                  internal only — not exposed via Ingress)       │
   └──────────────────────────────────────────────────────────────────┘

   Admission chain for every pod CREATE:
     API server ──▶ PSS restricted ──▶ Kyverno webhook ──▶ etcd
                    (root, caps,        (:latest, limits,
                     seccomp, PE)        RO-rootfs, signatures)
```

---

## 3. Prerequisites

| Tool | Version used | Notes |
|---|---|---|
| Docker | 29.0.1 | Docker Desktop / WSL2 backend |
| k3d | 5.9.0 | `winget install k3d.k3d` |
| kubectl | 1.34.1 | |
| kubeseal | 0.27.1 | binary from the Sealed Secrets release |
| Bash | Git Bash on Windows | scripts are POSIX sh |

Cluster components installed by `deploy.sh`: Sealed Secrets `v0.27.1`,
Kyverno `v1.13.4`, ingress-nginx `v1.11.3`.

---

## 4. Step-by-step reproduction

```bash
cd task-1-workload-hardening
git clone --depth 1 https://github.com/bhabani-dodo/ledger-api-assignment.git app-source  # if absent

./scripts/deploy.sh          # build, cluster, controllers, workload
./scripts/seal-secret.sh     # re-seal for THIS cluster's key (see note)
./scripts/verify.sh          # 17 checks
```

> **Re-sealing is expected on a new cluster.** A `SealedSecret` is encrypted to
> one controller keypair. A freshly created cluster generates a new key, so the
> committed ciphertext will not decrypt — run `seal-secret.sh`, then re-run
> `deploy.sh`. That is the security property working as designed, not a bug.

Demonstrate the guardrail rejecting the original insecure Deployment:

```bash
kubectl apply -f app-source/deploy/deployment.yaml
kubectl get pods -n payments      # none — every replica refused
```

---

## 5. Verification

`./scripts/verify.sh` — **17 passed, 0 failed**:

| # | Check | Result |
|---|---|---|
| 1 | ledger-api has ready replicas | PASS |
| 2 | Runs as uid 10001, not root | PASS |
| 3 | Write to `/` refused (read-only rootfs) | PASS |
| 4 | `/tmp` writable via emptyDir | PASS |
| 5 | No ServiceAccount token in pod | PASS |
| 6 | caps `["ALL"]` dropped, seccomp `RuntimeDefault`, no priv-esc | PASS |
| 7 | No leaked credential literal under `manifests/` | PASS |
| 8 | 4 non-compliant pods rejected (root, `:latest`, no limits, RW rootfs) | PASS ×4 |
| 9 | 3 personas cannot read Secrets or exec | PASS ×3 |
| 10 | `reporting → ledger-api` HTTP 200; `/summary` leaks no PANs | PASS ×2 |

### Runtime proof (excerpt)

```
$ kubectl exec ledger-api-... -- id
uid=10001(ledger) gid=10001(ledger) groups=10001(ledger)

$ kubectl exec ledger-api-... -- sh -c 'echo x > /payload.sh'
sh: 1: cannot create /payload.sh: Read-only file system

$ kubectl exec ledger-api-... -- ls /var/run/secrets/kubernetes.io/serviceaccount/
ls: cannot access '...': No such file or directory
```

### The original insecure Deployment, rejected

```
Warning: would violate PodSecurity "restricted:latest":
  allowPrivilegeEscalation != false, unrestricted capabilities,
  runAsNonRoot != true, seccompProfile

$ kubectl get deploy ledger-api -n payments
NAME         READY   UP-TO-DATE   AVAILABLE
ledger-api   0/3     0            0            ← zero pods admitted
```

---

## 6. Evidence

| File | Contents |
|---|---|
| `evidence/01-pss-rejects-insecure-deployment.txt` | Original starter Deployment refused, 0/3 pods |
| `evidence/02-admission-policies-reject.txt` | 4 violation classes rejected; PSS vs Kyverno attribution |
| `evidence/03-rbac-least-privilege.txt` | Persona matrix, workload SA has no permissions/token |
| `evidence/04-ingress-tls-headers.txt` | HTTPS through the Ingress returns 200 with all three security headers |

Screenshots belong in `screenshots/` (see `docs/screenshots-guide.md`).

---

## 7. Bonus items completed

- **Persona RBAC** — `developer` / `operator` / `admin` with least privilege,
  plus an unbound `breakglass-exec` Role. No persona can read Secrets or exec.
- **PSS `restricted` at the namespace** — all three modes (enforce/audit/warn),
  version-pinned to `latest`.
- **Admission policy rejecting the original insecure Deployment** — captured in
  `evidence/01`, with all four violations named.
- Extras beyond the ask: startup probes, `maxUnavailable: 0` rollouts,
  topology spread, data-minimising neighbour, PCI scope labelling, and a
  build-blocking secret-literal check.

### A judgement call worth highlighting

The Ingress originally carried a `configuration-snippet` annotation to set
`X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`. ingress-nginx
**rejected it**: snippets are disabled by default from v1.9 onward.

That default is correct, so I did not override it. A snippet injects raw nginx
directives from a *namespaced* object into the *shared* controller
configuration — meaning anyone who can create an Ingress in any namespace can
influence how traffic is proxied for other tenants. That is the class of issue
behind CVE-2021-25742 and CVE-2023-5044. Enabling `allow-snippet-annotations`
to add three response headers would trade a genuine cross-tenant escalation
path for a cosmetic win.

The headers are instead set in the **controller's own ConfigMap**
(`ingress-nginx/custom-headers`), which only a cluster administrator can edit.
Same outcome, no shared-config injection surface — verified in
`evidence/04-ingress-tls-headers.txt`.

---

## 8. Known limitations / what I'd do with more time

1. **EOL base image and 2018-era dependencies remain.** `python:3.6-slim`,
   Flask 0.12.2, PyYAML 5.1, requests 2.19.1. Upgrading means rewriting the app,
   which would destroy the Task 4 target. **Task 2's Trivy/Grype gate is
   expected to flag these, and that firing is the demonstration that the gate
   works.** Real remediation: port to Python 3.12 + Flask 3.x behind gunicorn.

2. **Image signing is `Audit`, not `Enforce`.** Task 1 uses locally-built images
   that are side-loaded and never pushed, so there is no signature to verify.
   Setting `Enforce` would block the very workload being deployed. Flips to
   `Enforce` (with `mutateDigest: true`) in Task 2 once GHCR images are
   cosign-signed. The policy already targets the GHCR paths.

3. **Images use version tags, not digests.** `ledger-api:0.1.0` should be
   `@sha256:…`. Deferred to Task 2 where CI produces the digest.

4. **No NetworkPolicy yet** — deliberately Task 3's scope (default-deny plus
   identity-based mesh authz, layered).

5. **Single-node cluster, `topologySpreadConstraints` set to `ScheduleAnyway`.**
   On a real multi-node cluster this becomes `DoNotSchedule` with a PodDisruptionBudget.

6. **`reporting` builds `FROM ledger-api`** to reuse cached layers on a
   memory-constrained machine. In production these would be independent images
   from a shared digest-pinned base — chaining them means a ledger-api rebuild
   silently rebuilds reporting.

7. **No CPU limit** (memory only). Intentional: CFS throttling adds tail latency
   on a payments path, and memory is the incompressible resource. Revisit with
   real load data.

### Environment note

Built on a 7.3 GB laptop where Docker Desktop's VM gets ~3.7 GB. **kind could
not create a cluster** — its node never reached systemd's multi-user target
(`could not find a log line that matches "Reached target Multi-User System"`),
including as a single node. **k3d/k3s boots reliably in ~2 minutes** at that
memory, so the tooling was switched; the assessment permits kind/k3d/minikube
equally. Two Windows-specific workarounds are baked into `deploy.sh`: BuildKit
cannot read through OneDrive reparse points (build context is copied to a temp
dir), and k3d writes `host.docker.internal` into the kubeconfig which resolves
to the LAN IP (rewritten to loopback).
