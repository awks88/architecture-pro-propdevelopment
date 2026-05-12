# Task7: PodSecurity / OPA Gatekeeper audit

## Что сделано

1. Создан namespace `audit-zone` с PodSecurity level `restricted`.
2. Добавлены небезопасные Pod-манифесты:
   - privileged container;
   - hostPath volume;
   - root UID 0.
3. Добавлены безопасные версии манифестов.
4. Установлен OPA Gatekeeper.
5. Добавлены ConstraintTemplates и Constraints:
   - запрет privileged containers;
   - запрет hostPath;
   - обязательный runAsNonRoot;
   - обязательный readOnlyRootFilesystem.
6. Добавлены verification scripts.

## Как проверить

```bash
kubectl apply -f 01-create-namespace.yaml

kubectl apply -f gatekeeper/constraint-templates/
kubectl apply -f gatekeeper/constraints/

bash verify/verify-admission.sh
bash verify/validate-security.sh
```

## Ожидаемый результат

Insecure manifests rejected.
Secure manifests accepted.
Namespace has pod-security.kubernetes.io/enforce=restricted.
Gatekeeper pods are Running.
Gatekeeper constraints exist.
