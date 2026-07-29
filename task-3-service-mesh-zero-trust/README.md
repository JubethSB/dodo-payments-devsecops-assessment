# Task 3 — Service Mesh & Zero-Trust (Istio)

Istio 1.30.3 on k3d, enforcing mTLS STRICT and identity-based authorization for
`ledger-api` and `reporting` in the `payments` namespace, with a Kubernetes
NetworkPolicy layer underneath.

The constraint that shaped every decision here: **Task 1's hardening had to
survive.** A default Istio install cannot inject into this namespace at all, and
the interesting part of this task is that the rejection is correct.

---

## 0. Verification status

`./scripts/verify-mesh.sh` exits **0** on this cluster. It asserts each result
at runtime and exits non-zero if any check fails, so a passing run is the claim.

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Istio installed, workloads in the mesh | **Verified** | [`01`](evidence/01-istio-install.txt), [`01-mesh`](evidence/01-mesh-injection-preserves-hardening.txt) |
| 2 | mTLS STRICT, plaintext refused | **Verified** | [`02`](evidence/02-mtls-strict-refuses-plaintext.txt) |
| 3 | Default-deny + identity-based allow | **Verified** | [`03`](evidence/03-authorization-identity.txt) |
| 4 | Cert issuance, rotation, trust root | **Verified** | [`04`](evidence/04-certificate-lifecycle.txt) |
| 5 | NetworkPolicy defence in depth | **Verified** | [`05`](evidence/05-networkpolicy-defence-in-depth.txt) |
| B | Gateway + canary manifests | Written, not runtime-tested | [`40-gateway-and-canary.yaml`](istio/40-gateway-and-canary.yaml) |
| B | PCI CDE scope analysis | Written | §7 |

The three results that carry the argument:

```
plaintext from outside the mesh   curl: (7) ... http_code=000   (no HTTP status)
reporting     -> ledger-api       HTTP 200
unauthorised  -> ledger-api       HTTP 403
```

with the Envoy verdict that explains the 403:

```json
"response_code": 403,
"response_code_details": "rbac_access_denied_matched_policy[none]",
"path": "/transactions", "authority": "ledger-api:8080"
```

The 403 case is only meaningful because the NetworkPolicy layer was explicitly
opened for that caller first (see §5). Otherwise the CNI drops the packet and
the mesh never gets to decide — which is exactly what happened on the first run,
and produced a 503 instead.

**Not runtime-tested:** the ingress gateway and canary manifests. No gateway pod
is deployed on this single-node cluster, and `istioctl x describe` reports
`Skipping Gateway information (no ingress gateway pods)`.

---

## 1. Approach & design decisions

### 1.1 istio-cni is not optional, and that is the point

Default sidecar injection adds an `istio-init` container that programs the pod's
iptables to redirect traffic through Envoy. It needs `NET_ADMIN` and `NET_RAW`.

The `payments` namespace enforces Pod Security Standards `restricted`, which
permits adding no capability except `NET_BIND_SERVICE`. Task 1's Kyverno policy
`require-drop-all-capabilities` rejects it independently, at `Enforce`. So a
default install is refused at admission.

Three ways out:

| Option | Verdict |
|---|---|
| Relax `payments` to `baseline` | **Rejected.** Undoes the central control of Task 1 so that Task 3 is easier to install. Weakening a security boundary to fit a tool is the wrong trade. |
| Ambient mode (ztunnel, no sidecars) | **Considered.** Lower memory, no `NET_ADMIN` anywhere. Not chosen because L7 authorization still needs waypoint proxies, and the per-workload certificate inspection this task asks to evidence is sidecar-shaped. Worth revisiting. |
| `istio-cni` | **Chosen.** iptables programming moves to a privileged DaemonSet in `istio-system`, once per node instead of once per pod. App pods get no elevated capabilities. |

The honest cost of istio-cni: **the privilege did not disappear, it moved.** The
CNI agent is a node-level component that can rewrite any pod's networking. That
is a better place for it — one audited component in a namespace only cluster
admins can write to, rather than a capability grant duplicated into every
workload — but it is a relocation of trust, not an elimination of it.

### 1.2 Authentication and authorization are kept separate

`PeerAuthentication` STRICT proves a caller holds a certificate issued by this
mesh's CA. It says nothing about *which* workload it is. Every meshed pod in the
cluster has a valid certificate, so STRICT alone means **authenticated**, not
**authorised**.

Conflating the two is a common way a mesh ends up trusted more than it deserves.
They are separate objects here, and they fail differently — which is what makes
the evidence meaningful:

| Failure | Symptom |
|---|---|
| Plaintext against STRICT | Transport-level reset. **No HTTP status.** |
| Valid cert, wrong identity | **HTTP 403** + RBAC access-denied log line |

If both produced the same symptom, the mesh would be indistinguishable from a
firewall and there would be no evidence identity was doing any work.

### 1.3 Authorization keys on SPIFFE identity, never on IP

```yaml
principals:
  - cluster.local/ns/payments/sa/reporting
```

Taken from the client certificate presented during the mTLS handshake:
`spiffe://cluster.local/ns/payments/sa/reporting`.

Why not an IP or CIDR:

- **Pod IPs are recycled.** An allow-list entry for `10.42.0.29` silently
  transfers authority to whatever workload lands on that address next.
- **An IP is an assertion by the network.** A SPIFFE ID is an assertion backed
  by a private key the workload had to prove possession of. Only a pod running
  under the `reporting` ServiceAccount can obtain it.
- **It survives rescheduling and scaling** without anyone editing policy, so the
  policy stays correct instead of drifting into a stale list nobody trusts.

This is where Task 1's dedicated ServiceAccounts pay off. Had both services
shared `default`, there would be no identity to key on.

### 1.4 Default-deny is an empty ALLOW policy, not a DENY policy

```yaml
kind: AuthorizationPolicy
metadata:
  name: default-deny-all
spec: {}
```

An `ALLOW` policy that selects every workload and permits no rule denies
everything. It is not a no-op. Istio evaluates `CUSTOM` → `DENY` → `ALLOW`, and
within `ALLOW` the rule is: if any ALLOW policy matches the workload, the request
must match at least one of them.

The consequence is the property that makes this zero-trust rather than a
firewall with a nice UI: **a new workload in the namespace has no reachability
until someone writes a rule for it.**

---

## 2. Architecture

```
                       ┌───────────── istio-system ─────────────┐
                       │  istiod (CA + XDS)   istio-cni-node    │
                       └───────┬────────────────────┬───────────┘
                       SDS/XDS │ 15012              │ programs iptables
                               │                    │ (no NET_ADMIN in pods)
   ┌───────────────────────────┼────────────────────┼──────────────────┐
   │ payments  (PSS restricted, istio-injection=enabled)               │
   │                                                                   │
   │   reporting ──────── mTLS ────────▶ ledger-api                    │
   │   sa/reporting     ALLOW GET        sa/ledger-api                 │
   │                    /transactions    ★ PCI CDE — holds PANs        │
   │                                                                   │
   │   unauthorised-client ──── mTLS ──✗ 403 RBAC denied               │
   │   sa/unauthorised-client        (valid cert, wrong identity)      │
   │                                                                   │
   │   NetworkPolicy: default-deny ingress AND egress underneath all   │
   └───────────────────────────────────────────────────────────────────┘
              ▲
    plaintext │ ✗ connection reset (no HTTP status)
   mesh-outsider ns (no sidecar)
```

---

## 3. Prerequisites

- Docker Desktop **running** (see §7 — this is the environment's sharpest edge)
- k3d cluster `ledger` from Task 1
- `kubectl`, `k3d`; `istioctl` is installed automatically by the install script

---

## 4. Reproduction

```bash
cd task-3-service-mesh-zero-trust
./scripts/restore-baseline.sh   # reporting + 2 replicas, ArgoCD parked
./scripts/install-istio.sh      # istioctl, CNI path guard, install, inject
kubectl apply -f istio/10-peer-authentication.yaml
kubectl apply -f istio/30-unauthorised-client.yaml
kubectl apply -f istio/20-authorization-policy.yaml
kubectl apply -f networkpolicy/
./scripts/verify-mesh.sh        # runs the assertions, writes evidence/
```

Afterwards, `./scripts/restore-argocd.sh` un-parks ArgoCD — GitOps drift
detection and self-heal are **off** until you do.

### If you rebuild the cluster first, the order matters

Getting this wrong costs a full rebuild, so it is worth stating explicitly.
**Seal after the cluster exists, never before:**

```bash
cd ../task-1-workload-hardening
./scripts/deploy.sh --recreate   # WILL fail at the SealedSecret step. Expected.
./scripts/seal-secret.sh         # now seals against the NEW controller keypair
./scripts/deploy.sh              # no --recreate; completes the deploy
```

The tempting shortcut — `./scripts/seal-secret.sh && ./scripts/deploy.sh --recreate`
— seals against the cluster that is about to be deleted. `--recreate` then
destroys it, the new sealed-secrets controller generates a fresh keypair, and
the ciphertext you just wrote is addressed to a private key that no longer
exists:

```
Failed to unseal: no key could decrypt secret (DB_PASSWORD, STRIPE_API_KEY)
[fail] cannot continue without the Secret
```

That is the SealedSecret guarantee working, not a bug — the same property
documented in
[`task-1/evidence/05-sealedsecret-key-binding.txt`](../task-1-workload-hardening/evidence/05-sealedsecret-key-binding.txt).
`deploy.sh` aborting there is correct behaviour: it refuses to bring up a
service with missing credentials rather than deploying it half-configured.

The downstream symptom is confusing if you do not connect it back:
`restore-baseline.sh` then reports
`Error from server (NotFound): deployments.apps "ledger-api" not found`,
because `deploy.sh` never got far enough to create it.

### The CNI path guard

`install-istio.sh` refuses to install unless the CNI directories declared in
`istio/00-istio-install.yaml` match the running node. On k3s the real paths are
**not** the upstream defaults:

```
cniConfDir: /var/lib/rancher/k3s/agent/etc/cni/net.d
cniBinDir:  /bin
```

Point the installer at `/opt/cni/bin` and you get a DaemonSet that starts, reports
Ready, and silently redirects nothing. The symptom is "mTLS doesn't work", which
sends you to debug `PeerAuthentication` instead of the install. The guard checks
for actual plugin binaries, not just that a directory exists.

---

## 5. Defence in depth: what each layer catches

**NetworkPolicy catches what the mesh cannot:**

- Traffic that never reaches a sidecar — a pod created without the injection
  label has *no enforcement point*, and every Istio policy here is silent about
  it. The CNI still applies.
- A compromised workload that bypasses its own proxy. Envoy runs *in* the pod;
  anything with enough control to bypass the iptables redirect has bypassed
  authorization with it. The CNI is outside that blast radius.
- Control-plane outage. Sidecars keep last-known config, but new pods come up
  unconfigured. NetworkPolicy has no such dependency.

**The mesh catches what NetworkPolicy cannot:**

- **Identity.** `reporting` and `unauthorised-client` share a namespace, a node
  and a pod CIDR. At L3/L4 there is nothing to tell them apart, so no
  NetworkPolicy can admit one and refuse the other.
- **HTTP semantics.** "GET /transactions but not POST" is not expressible in a
  policy that sees a TCP connection to port 8080.

**Order, and a diagnostic that falls out of it:** the CNI drops packets before
Envoy sees them, so a request refused by NetworkPolicy produces a timeout with
**no entry in the sidecar access log**. A denial invisible in the Istio logs was
dropped below the mesh — which tells you immediately which layer to debug.

### The NetworkPolicy trap worth knowing

`networkpolicy/10-allow-service-paths.yaml` contains an explicit kubelet-probe
allow. Omitting it is **silently destructive**: probes arrive from the *node*,
not from a pod, so a namespace-wide default-deny drops them. Readiness fails, the
pod leaves its Service endpoints, liveness fails next and the kubelet restarts
the container. The namespace appears to enter a crash loop minutes after a
network policy is applied, which is easy to misattribute to the application or to
Istio.

Under Istio, probes are additionally rewritten to port 15020, so both the app
ports and 15020 must be reachable from the node.

Equally, the default-deny **egress** rule must permit istiod on 15012, or
certificate rotation breaks. Nothing fails immediately — existing certs keep
working — and then the namespace fails closed hours later when renewal is due.

---

## 6. Certificate lifecycle

**Issuance.** The injector mounts a projected ServiceAccount token with audience
`istio-ca`. This works even though the workloads set
`automountServiceAccountToken: false` — that field only suppresses the default
`kube-api-access` volume; Istio mounts its own, narrowly-audienced one.
`pilot-agent` generates a private key **in the pod**; only a CSR leaves the
sidecar. istiod validates the token via TokenReview, confirming the pod really
runs under that ServiceAccount, and signs.

The certificate is delivered over SDS and held **in memory** — not on disk, not
in a Secret. There is no at-rest copy for an attacker with etcd or volume access
to steal.

**Rotation.** Default lifetime 24h, renewed at ~50% (roughly every 12h), without
restarting the pod. Short lifetimes are why there is no CRL: revocation is
achieved by declining to renew, bounding damage from a leaked key to hours rather
than relying on every peer honouring a revocation list.

**Trust root.** istiod is the CA. On a fresh install it self-generates a root
into `istio-ca-secret` in `istio-system`, and distributes the public cert to
every namespace via the `istio-ca-root-cert` ConfigMap.

> **Limitation for a real PCI deployment.** A self-signed root generated by
> istiod means the CA private key lives in a Kubernetes Secret, readable by
> anyone with `get secrets` in `istio-system`, and compromising it forges **any**
> workload identity in the mesh. Production should make istiod an intermediate
> under an offline or HSM-backed root, so a cluster compromise costs one
> revocable intermediate rather than the whole trust domain.

---

## 7. PCI CDE scope

`ledger-api`'s `GET /transactions` returns full PANs. `reporting` deliberately
does not propagate them — it aggregates by currency and status, returning counts
and totals only.

- **`ledger-api` is in the CDE.** It holds and returns cardholder data and has
  exactly one legitimate caller. It is **not** exposed through the ingress
  gateway; doing so would place a CDE system on the edge, making every
  internet-facing control in-scope for assessment.
- **`reporting` is out of scope by construction**, because the data it emits
  contains no cardholder data.

This is scope reduction by **data minimisation** rather than network drawing, and
it is the more durable of the two: a firewall rule can be changed by anyone with
firewall access, whereas `reporting` cannot leak a PAN it never receives.

The gateway terminates TLS, so traffic is briefly in cleartext *inside the
gateway process* — which is why the gateway is itself in CDE scope and must be
treated as a cardholder-data system even though it stores nothing.

---

## 8. Known limitations

- **The `172.19.0.0/16` CIDR** in the kubelet-probe NetworkPolicy is specific to
  this k3d cluster's docker network. It must be changed for any other cluster.
  It is an `ipBlock` rather than a `podSelector` because the probe source is not
  a pod; `0.0.0.0/0` would have worked and would have undone the default-deny for
  every external source at the same time.
- **Single-node cluster**, so the istio-cni DaemonSet, PodDisruptionBudgets and
  replica spreading are all untested in any meaningful sense.
- **Self-signed trust root**, as above.
- **ArgoCD is parked** for the duration of Task 3 and does not know about the
  Istio objects. If it is un-parked while Task 3 manifests are applied but not
  committed to the GitOps path, `selfHeal` will revert them.

---

## 9. Environment

This machine's WSL VM was shutting down 60 seconds after the last WSL handle
closed, taking the Docker daemon and every container with it. It presented as a
k3s crash loop with a `cgroup`/`systemd` error that reads like memory pressure.
It was not. Full writeup, including why exit code 0 was the clue that broke it
open, in [`evidence/00-environment-triage.txt`](evidence/00-environment-triage.txt).

**Docker Desktop must be running before any of this works.** Its backend service
is `Manual`/`Stopped` and starting it requires UAC. Without it, nothing manages
container lifecycle across a WSL VM suspend and the cluster is killed repeatedly
— which also killed CoreDNS, at which point every name in the cluster stops
resolving and the failures look like mesh problems.
