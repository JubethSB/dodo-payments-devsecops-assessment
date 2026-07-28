#!/usr/bin/env bash
#
# Task 1 — end-to-end reproduction.
#
# Builds the hardened images, creates a local k3d cluster, installs the
# Sealed Secrets and Kyverno controllers, and deploys the hardened workload.
# Idempotent: safe to re-run.
#
#   ./scripts/deploy.sh              # full build + deploy
#   ./scripts/deploy.sh --recreate   # tear the cluster down first
#
set -euo pipefail

CLUSTER=ledger
NS=payments
LEDGER_IMAGE=ledger-api:0.1.0
REPORTING_IMAGE=reporting:0.1.0
SEALED_SECRETS_VERSION=v0.27.1
KYVERNO_VERSION=v1.13.4

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH"; }
need docker; need k3d; need kubectl; need kubeseal

docker info >/dev/null 2>&1 || die "Docker daemon is not running."

# ── Build context workaround ────────────────────────────────────────────────
# This repo may live under a OneDrive-synced path. OneDrive uses reparse
# points that BuildKit cannot read through — it fails with
# "invalid file request Dockerfile". Copying the build context to a plain
# local temp dir sidesteps it. Harmless on non-OneDrive checkouts.
BUILD_TMP="$(mktemp -d)"
trap 'rm -rf "$BUILD_TMP"' EXIT

# ── 1. Images ───────────────────────────────────────────────────────────────
log "Building $LEDGER_IMAGE (hardened: multi-stage, non-root uid 10001)"
mkdir -p "$BUILD_TMP/ledger"
cp "$HERE/app-source/app/app.py" "$HERE/app-source/app/requirements.txt" "$BUILD_TMP/ledger/"
cp "$HERE/app-image/Dockerfile" "$BUILD_TMP/ledger/Dockerfile"
docker build -q -t "$LEDGER_IMAGE" "$BUILD_TMP/ledger"

log "Building $REPORTING_IMAGE (neighbour service, non-root uid 10002)"
mkdir -p "$BUILD_TMP/reporting"
cp "$HERE/neighbour-source/app.py" "$HERE/neighbour-source/Dockerfile" "$BUILD_TMP/reporting/"
docker build -q -t "$REPORTING_IMAGE" "$BUILD_TMP/reporting"

log "Verifying both images are non-root"
for img in "$LEDGER_IMAGE" "$REPORTING_IMAGE"; do
  uid="$(docker run --rm --entrypoint sh "$img" -c 'id -u')"
  [ "$uid" != "0" ] || die "$img runs as root (uid 0)"
  printf '    %-22s uid=%s  OK\n' "$img" "$uid"
done

# ── 2. Cluster ──────────────────────────────────────────────────────────────
if [ "${1:-}" = "--recreate" ]; then
  log "Deleting existing cluster"
  k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
fi

if k3d cluster list 2>/dev/null | grep -q "^$CLUSTER "; then
  log "Cluster '$CLUSTER' already exists — reusing"
else
  # k3d (k3s) rather than kind: on a 4 GB Docker VM a kind node could not
  # reach systemd's multi-user target, while k3s boots reliably in ~2 min.
  # --agents 0 keeps everything on the server node to conserve memory.
  log "Creating k3d cluster '$CLUSTER'"
  k3d cluster create "$CLUSTER" \
    --agents 0 \
    --port "8080:80@loadbalancer" \
    --port "8443:443@loadbalancer" \
    --k3s-arg "--disable=traefik@server:0" \
    --wait --timeout 300s
fi

# k3d writes host.docker.internal into the kubeconfig, which resolves to the
# LAN IP on Windows and times out. Rewrite it to loopback.
API_PORT="$(docker port "k3d-${CLUSTER}-serverlb" 6443/tcp | head -1 | sed 's/.*://')"
kubectl config set-cluster "k3d-${CLUSTER}" --server="https://127.0.0.1:${API_PORT}" >/dev/null
kubectl config use-context "k3d-${CLUSTER}" >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=180s >/dev/null

log "Importing images into the cluster"
k3d image import "$LEDGER_IMAGE" "$REPORTING_IMAGE" -c "$CLUSTER" >/dev/null

# ── 3. Namespace (PSS restricted) ───────────────────────────────────────────
log "Creating namespace with Pod Security Standards 'restricted'"
kubectl apply -f "$HERE/manifests/base/00-namespace.yaml"

# ── 4. Sealed Secrets ───────────────────────────────────────────────────────
log "Installing Sealed Secrets controller ($SEALED_SECRETS_VERSION)"
kubectl apply -f "https://github.com/bitnami-labs/sealed-secrets/releases/download/${SEALED_SECRETS_VERSION}/controller.yaml"
kubectl -n kube-system rollout status deploy/sealed-secrets-controller --timeout=300s

if [ -f "$HERE/manifests/secrets/ledger-api-sealedsecret.yaml" ]; then
  log "Applying committed SealedSecret (ciphertext only)"
  # NOTE: a SealedSecret is encrypted to one specific controller keypair. On a
  # freshly created cluster the controller generates a NEW key, so the
  # committed ciphertext cannot be decrypted and you must re-seal:
  #   ./scripts/seal-secret.sh
  kubectl apply -f "$HERE/manifests/secrets/ledger-api-sealedsecret.yaml"
  sleep 5
  if ! kubectl get secret ledger-api-secrets -n "$NS" >/dev/null 2>&1; then
    warn "SealedSecret did not unseal — this cluster's controller key differs."
    warn "Re-seal with: ./scripts/seal-secret.sh   then re-run this script."
    kubectl -n kube-system logs deploy/sealed-secrets-controller --tail=5 || true
    die "cannot continue without the Secret"
  fi
else
  die "No SealedSecret found. Run ./scripts/seal-secret.sh first."
fi

# ── 5. Kyverno ──────────────────────────────────────────────────────────────
log "Installing Kyverno ($KYVERNO_VERSION)"
# --server-side is required: the Kyverno CRDs exceed the 262144-byte limit on
# the kubectl.kubernetes.io/last-applied-configuration annotation that a
# client-side apply would try to write.
kubectl apply --server-side --force-conflicts \
  -f "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=420s

log "Applying admission policies"
kubectl apply -f "$HERE/manifests/policy/"

# ── 6. Workloads ────────────────────────────────────────────────────────────
log "Applying RBAC"
kubectl apply -f "$HERE/manifests/rbac/"

log "Deploying ledger-api and reporting"
kubectl apply -f "$HERE/manifests/base/10-ledger-api-configmap.yaml"
kubectl apply -f "$HERE/manifests/base/20-ledger-api-deployment.yaml"
kubectl apply -f "$HERE/manifests/base/30-ledger-api-service.yaml"
kubectl apply -f "$HERE/manifests/base/40-reporting.yaml"

kubectl -n "$NS" rollout status deploy/ledger-api --timeout=300s
kubectl -n "$NS" rollout status deploy/reporting  --timeout=300s

# Ingress last: it needs an ingress controller. traefik was disabled above, so
# install ingress-nginx. Non-fatal if it cannot start on a small node — the
# services are still reachable in-cluster.
log "Installing ingress-nginx and applying Ingress"
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/cloud/deploy.yaml
if kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=420s; then

  # Security response headers are applied through the CONTROLLER's ConfigMap,
  # not through a per-Ingress configuration-snippet annotation. ingress-nginx
  # v1.9+ rejects snippets by default, and that default is correct: a snippet
  # injects raw nginx directives from a namespaced object into the shared
  # controller configuration, so anyone able to create an Ingress could alter
  # proxying for other tenants (cf. CVE-2021-25742, CVE-2023-5044). This
  # ConfigMap is in the ingress-nginx namespace, so only a cluster admin can
  # change it.
  kubectl create configmap custom-headers -n ingress-nginx \
    --from-literal=X-Content-Type-Options=nosniff \
    --from-literal=X-Frame-Options=DENY \
    --from-literal=Referrer-Policy=no-referrer \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n ingress-nginx patch configmap ingress-nginx-controller --type merge \
    -p '{"data":{"add-headers":"ingress-nginx/custom-headers"}}'

  # Self-signed TLS for the local host name. Generated at deploy time and never
  # committed — a private key in git is the same class of mistake this task
  # exists to fix. Task 2/3 replace this with a real issuer / Istio gateway.
  CERT_TMP="$(mktemp -d)"
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_TMP/tls.key" -out "$CERT_TMP/tls.crt" \
    -subj "//CN=ledger.local" -addext "subjectAltName=DNS:ledger.local" 2>/dev/null
  kubectl create secret tls ledger-api-tls -n "$NS" \
    --cert="$CERT_TMP/tls.crt" --key="$CERT_TMP/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -
  rm -rf "$CERT_TMP"

  kubectl apply -f "$HERE/manifests/base/60-ingress.yaml"

  log "Ingress ready. Test with:"
  echo "    kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller 8443:443 &"
  echo "    curl -sk --resolve ledger.local:8443:127.0.0.1 https://ledger.local:8443/health"
else
  warn "ingress-nginx did not become ready (likely memory). Skipping Ingress."
  warn "The services remain reachable in-cluster via ClusterIP."
fi

log "Done. Verify with: ./scripts/verify.sh"
kubectl get pods -n "$NS" -o wide
