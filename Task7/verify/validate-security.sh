#!/usr/bin/env bash
set -euo pipefail

echo "== PodSecurity labels =="
kubectl get ns audit-zone -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}'

echo
echo "== Gatekeeper pods =="
kubectl get pods -n gatekeeper-system

echo
echo "== Gatekeeper ConstraintTemplates =="
kubectl get constrainttemplates

echo
echo "== Gatekeeper Constraints =="
kubectl get constraints

echo
echo "== Secure manifests server-side validation =="
kubectl apply --dry-run=server -f secure-manifests/

echo
echo "Security validation completed."
