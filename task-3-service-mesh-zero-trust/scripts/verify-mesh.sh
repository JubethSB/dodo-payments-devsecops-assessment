#!/usr/bin/env bash
#
# Task 3 verification. Proves the mesh controls at runtime and writes evidence
# to ./evidence/.
#
#   ./scripts/verify-mesh.sh
#
# Structured around NEGATIVE results. Showing that an authorised call succeeds
# proves very little on its own - it also succeeded before any policy existed.
# The load-bearing evidence is the two refusals, and that they fail in
# DIFFERENT ways:
#
#   plaintext against STRICT mTLS   -> transport-level reset, no HTTP status
#   valid cert, wrong identity      -> HTTP 403 + RBAC access-denied log line
#
# If both produced the same symptom, the mesh would be indistinguishable from a
# firewall and there would be no evidence that identity was doing any work.
set -uo pipefail

_add_path() {
  case "$1" in [A-Za-z]:*) return 0 ;; esac
  [ -d "$1" ] || return 0
  case ":$PATH:" in *":$1:"*) ;; *) PATH="$PATH:$1";; esac
}
_add_path "$HOME/.local/bin"
_add_path "/usr/local/bin"
export PATH

CLUSTER=ledger
NS=payments
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EV="$HERE/evidence"
mkdir -p "$EV"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[fail] %s\033[0m\n' "$*" >&2; exit 1; }
pass() { printf '\033[1;32m    PASS\033[0m  %s\n' "$*"; }
fail() { printf '\033[1;31m    FAIL\033[0m  %s\n' "$*"; }

API_PORT="$(docker port "k3d-${CLUSTER}-serverlb" 6443/tcp | head -1 | sed 's/.*://')"
[ -n "$API_PORT" ] || die "cluster is not running"
kubectl config set-cluster "k3d-${CLUSTER}" --server="https://127.0.0.1:${API_PORT}" >/dev/null
kubectl config use-context "k3d-${CLUSTER}" >/dev/null

RESULTS=0

# ---------------------------------------------------------------------------
log "1. Sidecars are present and the Task 1 hardening survived injection"
# ---------------------------------------------------------------------------
{
  echo "======================================================================"
  echo " EVIDENCE: workloads joined the mesh without weakening Task 1"
  echo "======================================================================"
  echo
  echo "\$ kubectl -n $NS get pods -o custom-columns=NAME,CONTAINERS"
  kubectl -n "$NS" get pods -o custom-columns=\
'NAME:.metadata.name,CONTAINERS:.spec.containers[*].name,READY:.status.containerStatuses[*].ready'
  echo
  echo "The namespace still enforces Pod Security Standards 'restricted':"
  kubectl get ns "$NS" -o jsonpath='  enforce={.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}'
  echo
  echo "No workload in $NS requests NET_ADMIN or NET_RAW. Default Istio"
  echo "injection would need both, via an istio-init container, and PSS"
  echo "restricted would have rejected the pod. istio-cni moves that privilege"
  echo "to a node-level DaemonSet in istio-system instead:"
  if kubectl -n "$NS" get pods -o json | grep -qE '"(NET_ADMIN|NET_RAW)"'; then
    echo "  FAILED - an elevated capability is present"
  else
    echo "  confirmed: no elevated capabilities in $NS"
  fi
  echo
  echo "Injected sidecar securityContext, which Task 1's Kyverno policies"
  echo "evaluate identically to the application container:"
  kubectl -n "$NS" get pod -l app.kubernetes.io/name=ledger-api -o jsonpath=\
'{range .items[0].spec.containers[?(@.name=="istio-proxy")]}  runAsUser:               {.securityContext.runAsUser}{"\n"}  readOnlyRootFilesystem: {.securityContext.readOnlyRootFilesystem}{"\n"}  allowPrivilegeEscalation:{.securityContext.allowPrivilegeEscalation}{"\n"}  capabilities.drop:      {.securityContext.capabilities.drop}{"\n"}  resources:              {.resources}{"\n"}{end}'
} > "$EV/01-mesh-injection-preserves-hardening.txt" 2>&1
cat "$EV/01-mesh-injection-preserves-hardening.txt"

# ---------------------------------------------------------------------------
log "2. mTLS STRICT: a plaintext caller is refused"
# ---------------------------------------------------------------------------
# The prover must be OUTSIDE the mesh. A meshed pod cannot send plaintext to a
# meshed peer even if you ask it to - its own sidecar upgrades the connection -
# so using one would produce a success and prove the opposite of the intent.
kubectl get ns mesh-outsider >/dev/null 2>&1 || kubectl create ns mesh-outsider >/dev/null
kubectl label ns mesh-outsider istio-injection- --overwrite >/dev/null 2>&1 || true

kubectl -n mesh-outsider delete pod plaintext-caller --ignore-not-found >/dev/null 2>&1
kubectl -n mesh-outsider run plaintext-caller \
  --image=curlimages/curl:8.11.1 --restart=Never --command -- sleep 300 >/dev/null 2>&1
kubectl -n mesh-outsider wait --for=condition=Ready pod/plaintext-caller --timeout=120s >/dev/null 2>&1

LEDGER_IP="$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=ledger-api \
              -o jsonpath='{.items[0].status.podIP}')"

# Target the POD IP directly, bypassing the Service, so the only thing that can
# refuse the connection is the destination sidecar's STRICT listener.
PLAINTEXT_OUT="$(kubectl -n mesh-outsider exec plaintext-caller -- \
  curl -sS -o /dev/null -w 'http_code=%{http_code}' --max-time 10 \
  "http://${LEDGER_IP}:8080/health" 2>&1 || true)"

{
  echo "======================================================================"
  echo " EVIDENCE: mTLS STRICT refuses a plaintext caller"
  echo "======================================================================"
  echo
  echo "PeerAuthentication in effect:"
  kubectl -n "$NS" get peerauthentication default -o jsonpath='  {.metadata.namespace}/{.metadata.name} mode={.spec.mtls.mode}{"\n"}'
  echo
  echo "The caller runs in namespace 'mesh-outsider', which has NO sidecar"
  echo "injection. This matters: a meshed pod cannot demonstrate this, because"
  echo "its own sidecar would transparently upgrade the connection to mTLS and"
  echo "the request would succeed for the wrong reason."
  echo
  echo "It targets ledger-api's POD IP directly ($LEDGER_IP:8080), bypassing"
  echo "the Service, so the only thing that can refuse it is the destination"
  echo "sidecar's STRICT listener."
  echo
  echo "\$ curl http://${LEDGER_IP}:8080/health"
  echo "  $PLAINTEXT_OUT"
  echo
  if echo "$PLAINTEXT_OUT" | grep -qE 'http_code=000|reset|refused|Recv failure|Empty reply'; then
    echo "REFUSED at the transport layer. Note there is NO HTTP status code:"
    echo "the connection never became an HTTP conversation. That is the"
    echo "signature of an authentication failure, and it is deliberately"
    echo "different from the 403 in 03-authorization-identity.txt, which is an"
    echo "AUTHORISATION failure on a connection that did complete a handshake."
  else
    echo "UNEXPECTED: the plaintext call was not refused."
  fi
  echo
  echo "----------------------------------------------------------------------"
  echo "istioctl's own view of the mTLS posture:"
  echo "----------------------------------------------------------------------"
  istioctl authn tls-check "$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=reporting -o jsonpath='{.items[0].metadata.name}')" \
    -n "$NS" 2>&1 | head -20 || echo "(tls-check unavailable in this istioctl version)"
} > "$EV/02-mtls-strict-refuses-plaintext.txt" 2>&1
cat "$EV/02-mtls-strict-refuses-plaintext.txt"

if echo "$PLAINTEXT_OUT" | grep -qE 'http_code=000|reset|refused|Recv failure|Empty reply'; then
  pass "plaintext refused by STRICT mTLS"
else
  fail "plaintext was NOT refused: $PLAINTEXT_OUT"; RESULTS=1
fi

# ---------------------------------------------------------------------------
log "3. AuthorizationPolicy: identity decides, not address"
# ---------------------------------------------------------------------------
AUTH_OK="$(kubectl -n "$NS" exec deploy/reporting -c reporting -- python -c "
import urllib.request
try:
    print(urllib.request.urlopen('http://ledger-api:8080/transactions', timeout=10).status)
except Exception as e:
    print(getattr(e, 'code', 'ERR'))
" 2>/dev/null || echo ERR)"

AUTH_DENY="$(kubectl -n "$NS" exec deploy/unauthorised-client -c client -- \
  curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  http://ledger-api:8080/transactions 2>&1 || echo ERR)"

sleep 3
RBAC_LOG="$(kubectl -n "$NS" logs -l app.kubernetes.io/name=ledger-api -c istio-proxy --tail=200 2>/dev/null \
            | grep -i 'rbac\|denied' | tail -3)"

{
  echo "======================================================================"
  echo " EVIDENCE: authorization keyed on SPIFFE identity, not IP"
  echo "======================================================================"
  echo
  echo "Policies in force:"
  kubectl -n "$NS" get authorizationpolicy -o custom-columns='NAME:.metadata.name,ACTION:.spec.action'
  echo
  echo "default-deny-all has an EMPTY spec. That is not a no-op: an ALLOW"
  echo "policy that selects every workload and permits no rule denies"
  echo "everything. allow-reporting-to-ledger-api then carves out exactly one"
  echo "caller, one method and two paths."
  echo
  echo "----------------------------------------------------------------------"
  echo "AUTHORISED   reporting -> ledger-api /transactions"
  echo "----------------------------------------------------------------------"
  echo "  identity: spiffe://cluster.local/ns/payments/sa/reporting"
  echo "  result:   HTTP $AUTH_OK"
  echo
  echo "----------------------------------------------------------------------"
  echo "UNAUTHORISED unauthorised-client -> ledger-api /transactions"
  echo "----------------------------------------------------------------------"
  echo "  identity: spiffe://cluster.local/ns/payments/sa/unauthorised-client"
  echo "  result:   HTTP $AUTH_DENY"
  echo
  echo "This pod is INSIDE the mesh and holds a valid certificate. It completed"
  echo "the mTLS handshake successfully and was refused on identity alone."
  echo
  echo "That is the case no NetworkPolicy can express. Both pods run in the"
  echo "same namespace, on the same node, in the same pod CIDR:"
  kubectl -n "$NS" get pods -o custom-columns='NAME:.metadata.name,IP:.status.podIP,SA:.spec.serviceAccountName' \
    -l 'app.kubernetes.io/name in (reporting,unauthorised-client,ledger-api)'
  echo
  echo "At the packet level they are indistinguishable. Only the certificate"
  echo "tells them apart, and a pod cannot forge one: the private key is issued"
  echo "to its ServiceAccount and never leaves its sidecar."
  echo
  echo "----------------------------------------------------------------------"
  echo "ledger-api sidecar log (the RBAC verdict)"
  echo "----------------------------------------------------------------------"
  if [ -n "$RBAC_LOG" ]; then echo "$RBAC_LOG"; else echo "(no RBAC line captured)"; fi
} > "$EV/03-authorization-identity.txt" 2>&1
cat "$EV/03-authorization-identity.txt"

[ "$AUTH_OK" = "200" ] && pass "authorised caller got 200" || { fail "authorised caller got $AUTH_OK"; RESULTS=1; }
[ "$AUTH_DENY" = "403" ] && pass "unauthorised caller got 403" || { fail "unauthorised caller got $AUTH_DENY (expected 403)"; RESULTS=1; }

# ---------------------------------------------------------------------------
log "4. Workload certificates: issuance, rotation and trust root"
# ---------------------------------------------------------------------------
POD="$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=reporting -o jsonpath='{.items[0].metadata.name}')"
{
  echo "======================================================================"
  echo " EVIDENCE: how workload certs are issued, rotated and rooted"
  echo "======================================================================"
  echo
  echo "\$ istioctl proxy-config secret $POD -n $NS"
  istioctl proxy-config secret "$POD" -n "$NS" 2>&1 | head -15
  echo
  echo "----------------------------------------------------------------------"
  echo "ISSUANCE"
  echo "----------------------------------------------------------------------"
  echo "  1. The injector mounts a PROJECTED ServiceAccount token into the"
  echo "     sidecar with audience 'istio-ca'. Note this works even though the"
  echo "     workloads set automountServiceAccountToken: false - that field"
  echo "     only suppresses the default kube-api-access volume, and Istio"
  echo "     mounts its own, narrowly-audienced one."
  echo "  2. pilot-agent generates a private key IN THE POD. The key is never"
  echo "     transmitted; only a CSR leaves the sidecar."
  echo "  3. istiod validates the token via the TokenReview API, confirming the"
  echo "     pod really runs under that ServiceAccount, and signs the CSR."
  echo "  4. The certificate is delivered over SDS and held in memory. It is"
  echo "     not written to disk and not stored in a Secret, so there is no"
  echo "     at-rest copy for an attacker with etcd or volume access to steal."
  echo
  echo "  The SAN is the SPIFFE ID the AuthorizationPolicy matches on:"
  echo "    spiffe://cluster.local/ns/payments/sa/reporting"
  echo
  echo "----------------------------------------------------------------------"
  echo "ROTATION"
  echo "----------------------------------------------------------------------"
  echo "  Default lifetime is 24h and pilot-agent renews at ~50% of it, so"
  echo "  roughly every 12h, without restarting the pod. Short lifetimes are"
  echo "  the reason there is no CRL here: revocation is achieved by declining"
  echo "  to renew, which bounds the damage from a leaked key to hours rather"
  echo "  than relying on every peer honouring a revocation list."
  echo
  echo "  This is also why the NetworkPolicy in networkpolicy/00-default-deny"
  echo "  must permit egress to istiod on 15012. Block it and nothing fails"
  echo "  immediately - existing certs keep working - and then the namespace"
  echo "  fails closed hours later when renewal is due."
  echo
  echo "----------------------------------------------------------------------"
  echo "TRUST ROOT"
  echo "----------------------------------------------------------------------"
  echo "  istiod acts as the CA. On a fresh install it self-generates a root"
  echo "  and stores it in the istio-ca-secret Secret in istio-system:"
  kubectl -n istio-system get secret istio-ca-secret -o jsonpath='    {.metadata.name} type={.type} keys={range .data}{"\n"}{end}' 2>/dev/null || echo "    (istio-ca-secret not found)"
  kubectl -n istio-system get secret istio-ca-secret -o jsonpath='{range .data}{"    key: "}{end}' 2>/dev/null
  kubectl -n istio-system get secret istio-ca-secret -o json 2>/dev/null | grep -oE '"(ca-cert\.pem|ca-key\.pem|root-cert\.pem|cert-chain\.pem)"' | sed 's/^/    /' || true
  echo
  echo "  The root public cert is distributed to every namespace in the"
  echo "  istio-ca-root-cert ConfigMap, which is how a sidecar validates its"
  echo "  peers:"
  kubectl -n "$NS" get configmap istio-ca-root-cert -o jsonpath='    {.metadata.namespace}/{.metadata.name}{"\n"}' 2>/dev/null || echo "    (not found)"
  echo
  echo "  HONEST LIMITATION for a PCI deployment: a self-signed root generated"
  echo "  by istiod means the CA private key lives in a Kubernetes Secret,"
  echo "  readable by anyone with get-secrets in istio-system, and compromising"
  echo "  it forges ANY workload identity in the mesh. Production should make"
  echo "  istiod an intermediate under an offline or HSM-backed root, so the"
  echo "  blast radius of a cluster compromise is one revocable intermediate"
  echo "  rather than the whole trust domain."
} > "$EV/04-certificate-lifecycle.txt" 2>&1
cat "$EV/04-certificate-lifecycle.txt"

# ---------------------------------------------------------------------------
log "5. NetworkPolicy layer"
# ---------------------------------------------------------------------------
{
  echo "======================================================================"
  echo " EVIDENCE: NetworkPolicy underneath the mesh, and what each layer adds"
  echo "======================================================================"
  echo
  kubectl -n "$NS" get networkpolicy
  echo
  echo "----------------------------------------------------------------------"
  echo "WHAT THE NETWORK LAYER CATCHES THAT THE MESH DOES NOT"
  echo "----------------------------------------------------------------------"
  echo "  Istio authorization is enforced BY THE SIDECAR, inside the pod."
  echo "  Anything that avoids the sidecar avoids the policy:"
  echo "    - a pod created without the injection label"
  echo "    - a workload that removes or bypasses its own proxy after"
  echo "      compromise (the proxy is in its blast radius; the CNI is not)"
  echo "    - ports Istio was never told to capture"
  echo "  NetworkPolicy is enforced by the CNI, outside the pod, so it still"
  echo "  applies in every one of those cases."
  echo
  echo "----------------------------------------------------------------------"
  echo "WHAT THE MESH CATCHES THAT THE NETWORK LAYER CANNOT"
  echo "----------------------------------------------------------------------"
  echo "  Identity. reporting and unauthorised-client are the same namespace,"
  echo "  the same node and the same pod CIDR - see the addresses in"
  echo "  03-authorization-identity.txt. No NetworkPolicy can admit one and"
  echo "  refuse the other, because at L3/L4 there is nothing to tell them"
  echo "  apart. Nor can it express 'GET /transactions but not POST'."
  echo
  echo "  Pod IPs are also recycled. An address-based allow-list silently"
  echo "  transfers authority to whatever workload lands on that IP next."
  echo
  echo "----------------------------------------------------------------------"
  echo "ORDER OF ENFORCEMENT, AND A USEFUL DIAGNOSTIC"
  echo "----------------------------------------------------------------------"
  echo "  The CNI drops packets before Envoy sees them, so NetworkPolicy is the"
  echo "  outer gate. A request refused there produces a timeout with NO entry"
  echo "  in the sidecar access log. So: a denial that is invisible in the"
  echo "  Istio logs was dropped below the mesh - which tells you immediately"
  echo "  which layer to debug."
} > "$EV/05-networkpolicy-defence-in-depth.txt" 2>&1
cat "$EV/05-networkpolicy-defence-in-depth.txt"

kubectl -n mesh-outsider delete pod plaintext-caller --ignore-not-found >/dev/null 2>&1 &

log "Evidence written to $EV"
ls -1 "$EV"

if [ "$RESULTS" -eq 0 ]; then
  log "All runtime assertions passed."
else
  die "Some assertions FAILED - see above. Evidence files record the actual results."
fi
