# Task 3 — Service Mesh & Zero-Trust: Engineering Handover

## 1. Objective

Tasks 1 and 2 secured the workload and its delivery. Task 3 secures **the traffic
between services**. The premise of zero-trust: the network is not a trust
boundary. Being inside the cluster shouldn't grant you the right to call
`ledger-api`. Every call must be *authenticated* (who are you, cryptographically)
and *authorised* (are you allowed to make this specific call).

The problem it solves is **lateral movement**. In a flat network, one compromised
pod can talk to everything. That's how a foothold becomes a breach. Task 3 makes
service-to-service calls prove identity with certificates and pass an explicit
allow-list keyed on *workload identity*, not IP — so a compromised neighbour
can't just reach the payments service because it happens to share a subnet.

Dodo included it because PCI-DSS wants the cardholder-data environment
*segmented* (Requirement 1) and traffic to it *encrypted* (Requirement 4), and
because "we have a firewall at the edge" is not segmentation once an attacker is
inside. The real-world risk mitigated: an attacker who lands anywhere in the
namespace pivoting freely to the service that holds card numbers.

## 2. Initial Problem

After Tasks 1–2 the workloads are hardened and signed, but:

- **Traffic is plaintext.** `reporting → ledger-api` is HTTP. Anything that can
  sniff the pod network reads PANs in flight.
- **Any pod can call `ledger-api`.** There's no authorization on the call. A
  compromised pod — or the "bare curl" pivot pod the starter shipped — can hit
  `/transactions` and pull card numbers.
- **Identity is by IP.** The only thing distinguishing callers is their address,
  and pod IPs are recycled, so any allow-list built on them is stale the moment a
  pod reschedules.

Attack scenario: exploit *any* service in the namespace (or drop a debug pod),
then `curl http://ledger-api:8080/transactions` and exfiltrate PANs — no
credential needed, because the network itself was the only gate and you're
already on it.

## 3. Design Decisions

**Istio, sidecar mode.** The brief names Istio. Sidecar (Envoy per pod) over
ambient mode because Task 3 has to *evidence* per-workload certificates and
`istioctl`-style mTLS inspection, which are sidecar-shaped; ambient's ztunnel is
attractive for memory but L7 authorization still needs waypoint proxies. Noted as
the thing I'd revisit.

**istio-cni — and this is the most important decision in the task.** Default
Istio injection adds an `istio-init` container that programs the pod's iptables
to redirect traffic through Envoy, and that needs `NET_ADMIN` + `NET_RAW`. The
`payments` namespace enforces PSS `restricted`, which permits adding *no*
capability beyond `NET_BIND_SERVICE`, and Task 1's Kyverno `drop-all-caps` policy
rejects it independently. **So a default Istio install literally cannot inject
into this namespace** — and that rejection is *correct behaviour*, not an
obstacle.

Three ways out, and why istio-cni:
1. *Relax the namespace to `baseline`.* Rejected — that undoes Task 1's central
   control to make Task 3 easier to install. Weakening a security boundary to fit
   a tool is exactly the trade this assessment is testing against.
2. *Ambient mode.* Genuinely attractive (no per-pod cap either), but the L7
   authorization + cert-inspection evidence is sidecar-shaped. Revisit.
3. *istio-cni (chosen).* Moves the iptables programming out of the pod into a
   privileged node-level DaemonSet in `istio-system`. App pods get **no** elevated
   capabilities, so the namespace stays `restricted` and Task 1 stands unmodified.

The honest cost, which I'd state to an interviewer unprompted: the privilege
didn't disappear, it *moved* — to one audited node component in a namespace only
cluster-admins can write to, instead of a capability grant duplicated into every
workload. That's a better place for it, but it's a relocation of trust, not an
elimination.

**mTLS STRICT, namespace-wide.** Istio injects in `PERMISSIVE` mode by default,
which accepts mTLS *and* plaintext on the same port — great for migration, wrong
as an end state, because a namespace looks encrypted on every dashboard while
still answering anyone who connects without a cert. `STRICT` removes the plaintext
listener. Namespace-wide (`PeerAuthentication` named `default`, no selector) so a
new workload is STRICT the moment it's created — relaxing it becomes a deliberate,
reviewable act rather than a thing you forget to add.

**Default-deny AuthorizationPolicy keyed on SPIFFE identity, not IP.** An empty
ALLOW policy that selects the whole namespace and permits nothing *is* a
default-deny (Istio's evaluation: an empty-spec ALLOW matches everything and
allows nothing). Then a narrow ALLOW carves out exactly `reporting → ledger-api`,
keyed on
`cluster.local/ns/payments/sa/reporting` — the SPIFFE ID from the client
certificate. Why identity over IP: pod IPs recycle (an IP allow-list silently
transfers authority to whatever lands on that address next); a SPIFFE ID is
backed by a private key only a pod running under that ServiceAccount can obtain.
This is where Task 1's dedicated SAs pay off — if both services shared `default`,
there'd be no identity to key on.

**NetworkPolicy underneath — defence in depth, and they catch different things.**
- *What NetworkPolicy catches that the mesh doesn't:* traffic that never reaches a
  sidecar — a pod with injection disabled, a workload that bypassed its own proxy
  after compromise (the proxy is in the pod's blast radius; the CNI is not),
  ports Istio wasn't told to capture. NetworkPolicy is enforced by the CNI,
  outside the pod.
- *What the mesh catches that NetworkPolicy can't:* identity. `reporting` and the
  unauthorised client are the same namespace, node, and pod CIDR — at L3/L4
  there's nothing to tell them apart, so no NetworkPolicy can admit one and refuse
  the other. Nor can it express "GET /transactions but not POST."
- Enforcement order is a useful diagnostic: the CNI drops packets before Envoy
  sees them, so a NetworkPolicy denial produces a timeout with *no* entry in the
  sidecar access log. A denial invisible in the Istio logs was dropped below the
  mesh — tells you which layer to debug.

**egress `REGISTRY_ONLY` + NetworkPolicy default-deny egress.** The mesh's
`outboundTrafficPolicy: REGISTRY_ONLY` and an egress default-deny close the
exfiltration path a CDE boundary exists to close. This is what makes Task 4's
RCE-to-exfil chain *fail* under the hardened stack — the attacker runs code but
can't phone home.

## 4. Implementation Walkthrough

Scripts: `restore-baseline.sh` → `install-istio.sh` → apply `istio/` + `networkpolicy/`
→ `verify-mesh.sh`.

- **[`istio/00-istio-install.yaml`](../../task-3-service-mesh-zero-trust/istio/00-istio-install.yaml)**
  — the `IstioOperator`. `profile: minimal` (istiod only; gateway added
  deliberately in the bonus). `cni.enabled: true`. istiod memory request trimmed
  from the **2048Mi default to 256Mi** — a request is a scheduling reservation,
  and 2Gi would reserve most of a 3.47 GiB node for a control plane serving four
  proxies. Proxy resources set explicitly because Task 1's `require-resource-limits`
  applies to *every* container including the injected sidecar. `accessLogFile:
  /dev/stdout` because Task 3 must evidence a *denial*, and without access logs a
  denial is indistinguishable from the upstream being down.
- **`install-istio.sh`** downloads istioctl, then **guards the CNI paths** —
  refuses to install unless the node's real CNI directories match what the config
  declares. This guard earned its place (see Problems); a misdirected CNI
  DaemonSet reports Ready and redirects nothing.
- **[`istio/10-peer-authentication.yaml`](../../task-3-service-mesh-zero-trust/istio/10-peer-authentication.yaml)**
  — `PeerAuthentication` `mtls.mode: STRICT`, namespace-wide.
- **[`istio/20-authorization-policy.yaml`](../../task-3-service-mesh-zero-trust/istio/20-authorization-policy.yaml)**
  — empty-spec `default-deny-all` + `allow-reporting-to-ledger-api` on the SPIFFE
  principal, scoped to `GET /transactions` and `/health`.
- **[`istio/30-unauthorised-client.yaml`](../../task-3-service-mesh-zero-trust/istio/30-unauthorised-client.yaml)**
  — the negative control: the starter's bare-curl pod, brought back, meshed, with
  its own SA. It holds a *valid* cert and is refused on *identity* — a 403, not a
  connection error. That distinction is the evidence.
- **[`networkpolicy/`](../../task-3-service-mesh-zero-trust/networkpolicy/)** —
  `default-deny` (ingress + egress), then explicit allows: DNS egress, istiod
  egress on **15012** (SDS/XDS — without it certs stop rotating and the namespace
  fails closed hours later), and kubelet probes (from the node's IP, which a
  namespace default-deny would otherwise drop, causing a fake crash-loop).
- **[`istio/40-gateway-and-canary.yaml`](../../task-3-service-mesh-zero-trust/istio/40-gateway-and-canary.yaml)**
  (bonus) — Ingress Gateway with TLS termination, and a 90/10 canary via
  `VirtualService` + `DestinationRule` subsets.

## 5. Deep Technical Explanation (interview language)

**Service mesh** — infrastructure that handles service-to-service traffic (mTLS,
routing, retries, observability) *outside* the app, via proxies. The app makes a
plain HTTP call; the mesh transparently secures and routes it.

**Istio / Envoy** — Istio is the control plane (`istiod`); Envoy is the data-plane
proxy that actually carries traffic. istiod configures the Envoys; Envoys enforce.

**Sidecar injection** — adding the Envoy proxy container to each pod. The mutating
webhook does it when the namespace is labelled `istio-injection=enabled`. In Istio
1.30 the proxy is a **native sidecar** — an `initContainer` with
`restartPolicy: Always`, not a normal container — which guarantees the proxy is
ready before the app starts (no startup race where the app emits unproxied
traffic).

**mTLS** — mutual TLS: both ends present certificates. Normal TLS authenticates
the server; mTLS also authenticates the *client*. That client cert is the
workload's identity.

**SPIFFE** — a standard for workload identity. The identity is a URI:
`spiffe://cluster.local/ns/payments/sa/reporting` — trust domain, namespace,
service account. It's encoded in the SAN of the workload cert.

**SPIRE** — the standalone SPIFFE runtime (issuer/attestor). Istio implements
SPIFFE identities itself via istiod-as-CA, so we don't run SPIRE here — worth
knowing the distinction: SPIFFE is the spec, SPIRE is one implementation, Istio is
another.

**PeerAuthentication** — the Istio resource that sets mTLS mode (STRICT /
PERMISSIVE / DISABLE) for workloads. STRICT = plaintext refused.

**AuthorizationPolicy** — the Istio resource for L7 authz. Evaluation order:
CUSTOM → DENY → ALLOW; an empty ALLOW that selects a workload denies everything
(the default-deny trick). Rules match on `principals` (SPIFFE), operations
(methods, paths), etc.

**NetworkPolicy** — the Kubernetes-native L3/L4 firewall, enforced by the CNI.
Selectors on pods/namespaces/IPs; can't see identity or HTTP.

**Gateway / VirtualService / DestinationRule** — the Gateway is the mesh's edge
(where external TLS terminates); the VirtualService is routing rules (host, path,
weight → which subset); the DestinationRule defines the subsets (e.g. `v1`/`v2`
by label) and policies. Canary = VirtualService weights + DestinationRule subsets.

**Certificate issuance & rotation, and the trust root** — istiod acts as the CA.
On install it self-generates a root and stores it in the `istio-ca-secret` Secret
in `istio-system`. Each sidecar's pilot-agent generates a private key *in the
pod*, sends a CSR (with a projected SA token as proof of identity) to istiod over
port 15012 (SDS); istiod validates the token via TokenReview, signs, and returns
the cert over SDS — it's held in memory, never written to disk or a Secret.
Default lifetime 24h, rotated at ~50% (≈12h) with no pod restart. Short lifetimes
are why there's no CRL: revocation is achieved by declining to renew, bounding a
leaked key to hours. Honest limitation for PCI: a self-signed istiod root means
the CA key lives in a Secret readable by anyone with `get secrets` in
`istio-system`; production should make istiod an *intermediate* under an offline
or HSM-backed root, so a cluster compromise is one revocable intermediate rather
than the whole trust domain.

## 6. Verification

[`verify-mesh.sh`](../../task-3-service-mesh-zero-trust/scripts/verify-mesh.sh),
re-run in the final audit: **all runtime assertions passed (exit 0)**, all 4
payments pods `2/2` (sidecar attached).

- **mTLS STRICT:** a pod in a *separate, unmeshed* namespace (`mesh-outsider`)
  curls `ledger-api`'s pod IP directly. Result: `http_code=000` — connection
  refused at the transport layer, *no HTTP status*. That's the signature of an
  authentication failure. The prover has to be outside the mesh; a meshed pod
  can't demonstrate this because its own sidecar would upgrade the connection.
  Evidence: [`evidence/02-mtls-strict-refuses-plaintext.txt`](../../task-3-service-mesh-zero-trust/evidence/02-mtls-strict-refuses-plaintext.txt).
- **Authorization:** `reporting → ledger-api/transactions` → **HTTP 200**;
  `unauthorised-client → ledger-api/transactions` → **HTTP 403**, with the Envoy
  log line `response_code_details: rbac_access_denied_matched_policy[none]`. Both
  pods, same namespace/node/CIDR — only the certificate tells them apart.
  Evidence: [`evidence/03-authorization-identity.txt`](../../task-3-service-mesh-zero-trust/evidence/03-authorization-identity.txt).

Why those outputs prove it: the two failures are *different* (transport reset vs.
403 with an RBAC verdict). If they were the same, the mesh would be
indistinguishable from a firewall and there'd be no evidence identity is doing any
work. The 403 with `rbac_access_denied` is authorization; the `http_code=000` is
authentication. Distinct proofs of distinct controls.

## 7. Problems Faced

**The CNI path that looked right and wasn't (cost a debugging cycle).** I set
`cniBinDir: /bin` — which *does* contain CNI plugins on a k3s node, and is what
most k3d+Istio recipes online tell you to use. Wrong. kubelet on this k3s build
loads plugins from `/var/lib/rancher/k3s/data/cni`, so istio-cni installed itself
where kubelet never looks. The failure mode is nasty: the CNI DaemonSet reports
Running and Ready, istiod logs injection normally, the pod is admitted — and then
*every* sandbox creation fails with `failed to find plugin "istio-cni" in path
[/var/lib/rancher/k3s/data/cni]`, so pods sit with no IP forever and nothing in
any Istio log says anything is wrong. Root cause: probing for "a directory that
contains plugins" instead of "the directory kubelet loads from." Fix:
`install-istio.sh` now resolves the path from kubelet's own `--cni-bin-dir` and
fails loudly on mismatch. Lesson: a guard that checks a *plausible* property gives
false confidence, which is worse than no guard.

**Native sidecars broke my "count the sidecars" check.** Istio 1.30 injects the
proxy as an `initContainer` (native sidecar), not a normal container. My first
verify script counted `.spec.containers[*].name` for `istio-proxy` and reported
*zero* sidecars on a completely healthy mesh. Fix: count `initContainers` too.
Lesson: know where your tooling actually puts things in the current version.

**The injector webhook fails *open*.** `failurePolicy: Ignore` means when istiod
is briefly unreachable, the apiserver admits the pod *without* a sidecar and
reports no error — the rollout just times out. My verify script now has a
precondition gate that refuses to generate evidence unless the workloads are
actually meshed, because evidence against an unmeshed pod ("authorised caller got
200") is worse than no evidence — it looks like a pass.

**`istioctl authn tls-check` doesn't exist in 1.x.** The brief references it; it
was removed. Fixed the evidence to use `istioctl x describe` + `proxy-config
secret` (the effective listener config and the issued cert), which is stronger
anyway — it shows what the proxy actually enforces.

**The environment fought the whole task** (documented in
`evidence/00-environment-triage.txt`): a WSL VM idle-suspend that killed the
cluster and *looked* like a k3s crash loop (clean exit 0 was the tell); a leftover
kind node eating 674 MB; CoreDNS dying after repeated hard kills. Root-caused each
before blaming Istio's footprint — which matters, because "the cluster keeps
dying" would otherwise have been pinned on sidecars the moment they appeared.

## 8. Interview Questions

1. **Why istio-cni instead of the default init container?** *Short:* the default
   needs `NET_ADMIN`, which PSS `restricted` forbids. *Deep:* default injection's
   `istio-init` programs iptables and needs `NET_ADMIN`/`NET_RAW`; the namespace
   is `restricted` and Kyverno drops all caps, so injection is rejected — correct
   behaviour. istio-cni moves that to a node DaemonSet so app pods need no caps.
   *Follow-up: where did the privilege go? → to one audited node component, not
   eliminated — a relocation of trust.*

2. **STRICT vs PERMISSIVE mTLS?** *Short:* PERMISSIVE accepts plaintext too.
   *Deep:* PERMISSIVE keeps a plaintext listener for migration, so the service
   looks encrypted while still answering un-authenticated callers; STRICT removes
   it. Namespace-wide default so new workloads are STRICT automatically.

3. **Why key authz on SPIFFE identity, not IP?** *Short:* IPs recycle, certs
   don't lie. *Deep:* a pod IP is reassigned to whatever lands there next, so an
   IP allow-list silently transfers authority; a SPIFFE ID is backed by a private
   key only a pod under that SA can get. Requires the dedicated SAs from Task 1.
   *Follow-up: how is the SPIFFE ID proven? → it's the SAN in the mTLS client cert
   istiod issued after TokenReview.*

4. **You have mTLS. Why also NetworkPolicy?** *Short:* they catch different
   failures. *Deep:* mesh authz is enforced by the in-pod sidecar, so anything
   that avoids the sidecar (unmeshed pod, bypassed proxy) avoids it; NetworkPolicy
   is CNI-enforced, outside the pod. Conversely NetworkPolicy can't see identity
   or HTTP verbs. *Follow-up: which fires first? → the CNI drops before Envoy, so
   a NetworkPolicy denial has no sidecar log entry — a diagnostic.*

5. **How are workload certs issued and rotated? Trust root?** *Short:* istiod is
   the CA; certs are 24h, rotated at ~12h over SDS; root in `istio-ca-secret`.
   *Deep:* pilot-agent makes a key in-pod, CSRs to istiod with a projected SA
   token, istiod validates via TokenReview and signs; cert lives in memory only.
   No CRL because short lifetimes make "decline to renew" the revocation.
   *Follow-up: PCI concern? → self-signed root's key sits in a Secret; make istiod
   an intermediate under an HSM root in prod.*

6. **How did you prove plaintext is actually refused?** *Short:* an unmeshed pod
   hitting the pod IP got `http_code=000`. *Deep:* it has to be unmeshed —
   otherwise the caller's own sidecar upgrades to mTLS and you prove the opposite.
   `000` = transport reset, no HTTP, which is authentication failing, distinct
   from the authz 403.

7. **Rapid-fire:**
   - *istiod vs Envoy?* control plane vs data-plane proxy.
   - *What's in port 15012?* SDS (certs) + XDS (config) from istiod.
   - *Canary mechanism?* VirtualService weights over DestinationRule subsets.
   - *Why `REGISTRY_ONLY` egress?* closes arbitrary outbound — the CDE exfil path.
   - *SPIFFE vs SPIRE?* the identity spec vs one runtime that implements it;
     Istio implements SPIFFE itself.

## 9. Design Defence

*"Why not just relax the namespace to make Istio install cleanly?"* — because that
deletes the central control of Task 1 to make Task 3 convenient. The whole
assessment is about not doing that. istio-cni keeps `restricted` intact; the extra
install complexity is the correct price.

*"mTLS everywhere is a lot of overhead. Justify it in a payments context."* — the
threat model is an attacker *inside* the perimeter, which is the realistic modern
case. Plaintext east-west traffic means one foothold reads PANs off the wire.
Envoy's mTLS overhead is small and measured; the alternative is an unencrypted CDE.

*"Isn't the AuthorizationPolicy redundant with the NetworkPolicy?"* — no, and this
is the key point: they operate on different information. The NetworkPolicy can't
distinguish `reporting` from the unauthorised client (same CIDR); only the
certificate can. And the NetworkPolicy still protects against a pod that dodged
its sidecar, which the AuthorizationPolicy can't. Each covers the other's gap.

*"You trust istiod as a CA — that's a single point of compromise."* — correct, and
I'd flag it unprompted: in production istiod should be an intermediate under an
offline/HSM root, so compromising the cluster forges identities only until you
revoke one intermediate, not forever. The local setup uses the self-signed default
and I documented the exact upgrade path.

## 10. Real Production Perspective

- **Mesh at scale:** multi-cluster Istio with a shared trust domain, or ambient
  mode to cut the per-pod proxy cost; istiod HA (multiple replicas, which a
  single-node local cluster can't do).
- **Identity:** istiod as intermediate CA under an enterprise root / HSM;
  SPIFFE/SPIRE if you need workload identity that spans beyond Kubernetes (VMs,
  other orchestrators).
- **Gateway:** the Ingress Gateway fronted by a cloud LB (ALB/NLB, App Gateway,
  GCLB) with real ACME/managed certs, WAF in front; ledger-api still never
  exposed there.
- **Policy:** AuthorizationPolicies and NetworkPolicies managed via GitOps
  (Task 2's pattern), reviewed like code; PCI CDE scope drawn as an explicit set
  of labelled namespaces with mesh + network policy at every edge.
- **Cloud specifics:** EKS/GKE/AKS all run Istio; managed meshes exist (GKE's
  Anthos Service Mesh, AWS App Mesh is the closest AWS-native analogue though
  Envoy-based Istio-on-EKS is common). The zero-trust *principles* — authenticate
  every call by identity, default-deny, defence-in-depth at L3/L4 and L7 — are
  identical; the control plane's hosting and the CA's backing change.
