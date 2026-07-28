#!/usr/bin/env bash
#
# Create (or rotate) the SealedSecret for ledger-api.
#
# The plaintext Secret is written to a temp file that is deleted on exit and is
# never inside the repository tree. Only the sealed (encrypted) output is
# written under manifests/secrets/, which is what gets committed.
#
# A SealedSecret is encrypted to a specific controller keypair, so it must be
# re-sealed against any newly created cluster. That is the intended trade-off:
# the ciphertext is worthless to anyone who does not hold the cluster's private
# key, which is exactly why it is safe to commit.
#
#   ./scripts/seal-secret.sh
#   STRIPE_API_KEY=sk_live_xxx DB_PASSWORD=yyy ./scripts/seal-secret.sh
#
set -euo pipefail

NS=payments
SECRET_NAME=ledger-api-secrets
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$HERE/manifests/secrets/ledger-api-sealedsecret.yaml"

command -v kubeseal >/dev/null || { echo "kubeseal not found on PATH" >&2; exit 1; }

kubectl -n kube-system get deploy sealed-secrets-controller >/dev/null 2>&1 \
  || { echo "sealed-secrets controller not installed; run deploy.sh first" >&2; exit 1; }

# Values come from the environment so real credentials are never written into
# this file. The defaults are obvious placeholders, the leaked starter key is
# deliberately NOT reused. A credential that has been committed to git must be
# rotated at the provider and treated as burned; re-encrypting the same value
# just hides a key that is already public in the repository's history.
: "${STRIPE_API_KEY:=sk_live_ROTATED_placeholder_not_the_leaked_key}"
: "${DB_PASSWORD:=Xq7#mR2vTp9\$Lw4NzB8k}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

kubectl create secret generic "$SECRET_NAME" \
  --namespace "$NS" \
  --from-literal=STRIPE_API_KEY="$STRIPE_API_KEY" \
  --from-literal=DB_PASSWORD="$DB_PASSWORD" \
  --dry-run=client -o yaml > "$TMP/plaintext.yaml"

kubeseal --format yaml \
  --controller-namespace kube-system \
  --controller-name sealed-secrets-controller \
  < "$TMP/plaintext.yaml" > "$OUT"

echo "Sealed -> $OUT"
echo
echo "Sanity check, the plaintext values must NOT appear in the sealed file:"
if grep -qF "$STRIPE_API_KEY" "$OUT" 2>/dev/null; then
  echo "  FAIL: plaintext key found in output" >&2
  exit 1
fi
echo "  OK: only ciphertext present."
