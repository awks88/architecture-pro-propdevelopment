#!/usr/bin/env bash
set -euo pipefail

echo "== Namespace labels =="
kubectl get ns audit-zone --show-labels

echo
echo "== Insecure manifests must be rejected =="
for file in insecure-manifests/*.yaml; do
  echo
  echo "Testing insecure manifest: $file"

  if kubectl apply --dry-run=server -f "$file"; then
    echo "ERROR: $file was accepted, but should be rejected"
    exit 1
  else
    echo "OK: $file was rejected"
  fi
done

echo
echo "== Secure manifests must be accepted =="
for file in secure-manifests/*.yaml; do
  echo
  echo "Testing secure manifest: $file"

  kubectl apply --dry-run=server -f "$file"
  echo "OK: $file passed server validation"
done

echo
echo "Admission verification completed successfully."
