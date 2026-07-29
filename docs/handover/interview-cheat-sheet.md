# Interview Cheat Sheet

Skim this the hour before. One-liners you can expand on demand.

## Architecture in one breath

A PCI-scoped `ledger-api` on k3d, hardened four ways: **workload** (non-root,
read-only rootfs, drop-all-caps, PSS restricted + Kyverno, SealedSecrets, scoped
RBAC), **supply chain** (GitHub Actions scans → GHCR → cosign keyless sign + SBOM
attest → ArgoCD pull-deploy), **network** (Istio mTLS STRICT + SPIFFE
AuthorizationPolicy + NetworkPolicy default-deny), and **validated by attacking
it** (4 exploited findings mapped back to the controls that stop them).

## End-to-end workflow

`git push` → CI scans (gitleaks/semgrep/trivy) → build to GHCR → trivy image scan
→ cosign sign + SBOM attest + verify → commit signed digest to gitops path →
ArgoCD pulls & reconciles → pod admitted through PSS + Kyverno (must be non-root,
signed, no `:latest`) → joins Istio mesh (sidecar via istio-cni) → mTLS STRICT +
default-deny authz on SPIFFE identity + NetworkPolicy underneath.

## Commands to remember

```bash
# cluster / kubeconfig (k3d API port changes on restart)
k3d cluster start ledger
API=$(docker port k3d-ledger-serverlb 6443/tcp | sed 's/.*://')
kubectl config set-cluster k3d-ledger --server=https://127.0.0.1:$API

# Task 1
kubectl get ns payments -o jsonpath='{.metadata.labels}'        # PSS labels
kubectl exec deploy/ledger-api -- id -u                          # 10001
kubectl auth can-i get secrets --as-group=dodo:payments-admins -n payments

# Task 2
cosign verify --certificate-identity-regexp '...' --certificate-oidc-issuer \
  https://token.actions.githubusercontent.com <img>@<digest>
argocd app get ledger-api                                        # sync/health

# Task 3
istioctl proxy-config secret deploy/reporting -n payments        # the workload cert
kubectl get peerauthentication,authorizationpolicy,networkpolicy -n payments
kubectl logs deploy/ledger-api -c istio-proxy | grep rbac        # the 403 verdict

# Task 4
curl -H 'Content-Type: application/x-yaml' --data-binary @gadget.yaml \
  http://127.0.0.1:18080/import                                  # RCE
curl 'http://127.0.0.1:18080/fetch?url=http://t4-internal/...'    # SSRF
```

## Files to know

| File | Why it matters |
|---|---|
| `task-1/manifests/base/00-namespace.yaml` | PSS restricted + `pci-scope: cde` |
| `task-1/manifests/policy/*.yaml` | Kyverno: non-root, no-latest, hardened-ctx, verify-sig |
| `task-1/manifests/rbac/10-persona-roles.yaml` | dev/operator/admin/breakglass; none can read secrets or exec |
| `task-1/manifests/secrets/*-sealedsecret.yaml` | ciphertext safe to commit |
| `.github/workflows/ci-cd.yml` | the whole pipeline + fail policies |
| `.gitleaks.toml` / `.trivyignore` / `.semgrepignore` | documented, path-scoped exceptions |
| `task-2/argocd/application.yaml` | pull-based GitOps, selfHeal, ignoreDifferences |
| `task-3/istio/00-istio-install.yaml` | istio-cni + trimmed istiod memory |
| `task-3/istio/10..30-*.yaml` | STRICT mTLS, default-deny authz, negative control |
| `task-3/networkpolicy/*.yaml` | L3/L4 default-deny + the allows the mesh needs |
| `task-4/pentest-report.md` | the standalone report |

## Debugging commands I actually used

```bash
docker inspect <c> --format '{{.State.ExitCode}} {{.State.OOMKilled}}'  # crash vs clean exit
kubectl -n payments describe pod <p> | sed -n '/Events:/,$p'            # why stuck
kubectl -n istio-system logs -l k8s-app=istio-cni-node                  # CNI health
docker exec k3d-ledger-server-0 ls /var/lib/rancher/k3s/data/cni        # where kubelet reads plugins
free -m                                                                  # the 3.7GB reality
```

## Security concepts (one-liners)

- **Least privilege** — grant exactly what's needed, nothing more. Drop-all-caps, no SA token.
- **Defence in depth** — layers that fail differently: PSS+Kyverno, mTLS+NetworkPolicy, sign+verify.
- **Blast radius** — what an attacker can reach *after* the first bug. Hardening shrinks it.
- **Secrets hygiene** — no plaintext in git; key never leaves the cluster (SealedSecrets).

## Zero-trust concepts

- Network location ≠ trust. Every call authenticated (mTLS) and authorised (SPIFFE).
- **Default-deny** then explicit allow-list. New workload = no reachability until a rule exists.
- **Identity over IP** — IPs recycle; a SPIFFE ID is backed by a private key.

## CI/CD & supply-chain concepts

- **Keyless signing** — Fulcio issues a ~10-min cert from your OIDC identity; Rekor logs it; no key at rest.
- **SBOM/attestation** — signed bill of materials; answers "are we exposed to CVE-X" fleet-wide.
- **Pull-based GitOps** — CI commits a digest; ArgoCD pulls. CI holds no cluster creds.
- **Fail policy** — block on fixable, warn+track on unfixable; a permanently-red gate gets disabled.

## Kubernetes concepts

- **Admission control** — apiserver validates/mutates before etcd. PSS is built-in; Kyverno is a webhook.
- **ServiceAccount / RBAC** — pod identity + Role/RoleBinding least privilege.
- **NetworkPolicy** — CNI-enforced L3/L4 firewall; identity-blind.
- **securityContext / seccomp / capabilities** — the per-pod kernel-level hardening knobs.

## Docker concepts

- **Multi-stage build** — build tools stay out of the runtime image; non-root final stage.
- **Digest vs tag** — digest is immutable bytes; tag can be repointed after review.
- **Read-only rootfs + tmpfs** — immutable image, writes go to a bounded in-memory emptyDir.

## Networking concepts

- **mTLS** — both ends present certs; the client cert is the workload identity.
- **Envoy sidecar** — per-pod proxy that enforces mTLS/authz; native sidecar = initContainer, ready before the app.
- **istio-cni** — moves iptables programming to a node DaemonSet so app pods need no `NET_ADMIN`.
- **Gateway/VirtualService/DestinationRule** — edge TLS / routing rules / subsets; canary = weights over subsets.
- **SDS on 15012** — how sidecars fetch and rotate certs from istiod.

## Pen-testing concepts

- **Passive vs active recon** — CT logs/DNS/TLS (no aggressive touch) vs probes/exploits (authorised target only).
- **CVSS v3.1** — `AV/AC/PR/UI/S/C/I/A`; S:C = impact crosses a trust boundary.
- **SSRF** — server fetches an attacker URL → internal services, cloud metadata.
- **Deserialization RCE** — `yaml.load` builds arbitrary objects; FullLoader<5.4 bypassed by CVE-2020-14343.
- **The chain** — RCE → read env secrets → exfiltrate; contained by non-root + egress default-deny.
