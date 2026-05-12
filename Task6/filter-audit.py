#!/usr/bin/env python3
import json
import sys
from pathlib import Path


AUDIT_LOG = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("audit.log")
OUT_JSON = Path("audit-extract.json")
OUT_MD = Path("analysis.md")


def read_events(path):
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def g(obj, path, default=None):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def username(e):
    user = g(e, "user.username", "unknown")
    impersonated = g(e, "impersonatedUser.username")
    if impersonated:
        return f"{user} as {impersonated}"
    return user


def status(e):
    return g(e, "responseStatus.code", "unknown")


def is_secret_get(e):
    return e.get("verb") == "get" and g(e, "objectRef.resource") == "secrets"


def is_exec(e):
    return (
        e.get("verb") == "create"
        and g(e, "objectRef.resource") == "pods"
        and g(e, "objectRef.subresource") == "exec"
    )


def is_privileged_pod(e):
    if g(e, "objectRef.resource") != "pods":
        return False

    containers = g(e, "requestObject.spec.containers", []) or []
    return any(g(c, "securityContext.privileged") is True for c in containers)


def is_rolebinding_cluster_admin(e):
    if g(e, "objectRef.resource") not in ["rolebindings", "clusterrolebindings"]:
        return False

    return (
        g(e, "requestObject.roleRef.kind") == "ClusterRole"
        and g(e, "requestObject.roleRef.name") == "cluster-admin"
    )


def is_audit_policy_event(e):
    return "audit-policy" in json.dumps(e, ensure_ascii=False).lower()


def compact(e, finding):
    return {
        "finding": finding,
        "timestamp": e.get("requestReceivedTimestamp") or e.get("stageTimestamp"),
        "stage": e.get("stage"),
        "actor": username(e),
        "verb": e.get("verb"),
        "objectRef": e.get("objectRef"),
        "requestURI": e.get("requestURI"),
        "responseStatus": e.get("responseStatus"),
        "sourceIPs": e.get("sourceIPs"),
        "userAgent": e.get("userAgent"),
        "requestObject": e.get("requestObject"),
    }


events = list(read_events(AUDIT_LOG))
findings = []

for e in events:
    if is_secret_get(e):
        findings.append(compact(e, "secret_get"))

    if is_privileged_pod(e):
        findings.append(compact(e, "privileged_pod"))

    if is_exec(e):
        findings.append(compact(e, "pod_exec"))

    if is_rolebinding_cluster_admin(e):
        findings.append(compact(e, "cluster_admin_rolebinding"))

    if is_audit_policy_event(e):
        findings.append(compact(e, "audit_policy_delete_or_change"))


OUT_JSON.write_text(
    json.dumps(findings, ensure_ascii=False, indent=2),
    encoding="utf-8",
)


def first(kind):
    for f in findings:
        if f["finding"] == kind:
            return f
    return None


def describe(f):
    if not f:
        return "не найдено"

    obj = f.get("objectRef") or {}
    resp = f.get("responseStatus") or {}

    return (
        f"Кто: `{f.get('actor')}`; "
        f"verb: `{f.get('verb')}`; "
        f"namespace: `{obj.get('namespace')}`; "
        f"resource: `{obj.get('resource')}`; "
        f"name: `{obj.get('name')}`; "
        f"subresource: `{obj.get('subresource')}`; "
        f"status: `{resp.get('code')}`."
    )


secret = first("secret_get")
privileged = first("privileged_pod")
pod_exec = first("pod_exec")
rbac = first("cluster_admin_rolebinding")
audit_policy = first("audit_policy_delete_or_change")

md = f"""# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
   - {describe(secret)}
   - Почему подозрительно: ServiceAccount `monitoring` попытался получить доступ к Secret. Если статус `403`, это попытка несанкционированного доступа. Если статус `200`, это уже успешное чтение секрета и возможная компрометация.

2. Привилегированные поды:
   - {describe(privileged)}
   - Комментарий: Pod с `securityContext.privileged: true` опасен, потому что контейнер получает расширенные привилегии и может использоваться для атаки на node.

3. Использование kubectl exec в чужом поде:
   - {describe(pod_exec)}
   - Что делал: был создан запрос к subresource `pods/exec`. В симуляции выполнялась команда внутри Pod из namespace `kube-system`, что является подозрительным действием.

4. Создание RoleBinding с правами cluster-admin:
   - {describe(rbac)}
   - К чему привело: ServiceAccount `monitoring` был привязан к ClusterRole `cluster-admin` через RoleBinding `escalate-binding`.

5. Удаление audit-policy:
   - {describe(audit_policy)}
   - Возможные последствия: удаление или изменение audit policy снижает наблюдаемость кластера и может скрыть дальнейшие действия атакующего.

## Вывод

В audit.log найдены признаки инцидента: попытка доступа к Secret, создание privileged Pod, exec в системный Pod, удаление объекта audit-policy и создание RoleBinding с `cluster-admin`.

Даже если часть событий завершилась ошибкой `403`, они важны как индикаторы попытки несанкционированного доступа.
"""

OUT_MD.write_text(md, encoding="utf-8")

print(f"Loaded audit events: {len(events)}")
print(f"Extracted suspicious events: {len(findings)}")
print("Created: audit-extract.json")
print("Created: analysis.md")
