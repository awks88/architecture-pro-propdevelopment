# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

1. Доступ к секретам:
   - Кто: `kubernetes-admin`; verb: `get`; namespace: `kube-system`; resource: `secrets`; name: `bootstrap-token-0umyzh`; subresource: `None`; status: `None`.
   - Почему подозрительно: ServiceAccount `monitoring` попытался получить доступ к Secret. Если статус `403`, это попытка несанкционированного доступа. Если статус `200`, это уже успешное чтение секрета и возможная компрометация.

2. Привилегированные поды:
   - Кто: `system:serviceaccount:kube-system:daemon-set-controller`; verb: `create`; namespace: `kube-system`; resource: `pods`; name: `None`; subresource: `None`; status: `201`.
   - Комментарий: Pod с `securityContext.privileged: true` опасен, потому что контейнер получает расширенные привилегии и может использоваться для атаки на node.

3. Использование kubectl exec в чужом поде:
   - не найдено
   - Что делал: был создан запрос к subresource `pods/exec`. В симуляции выполнялась команда внутри Pod из namespace `kube-system`, что является подозрительным действием.

4. Создание RoleBinding с правами cluster-admin:
   - Кто: `system:apiserver`; verb: `create`; namespace: `None`; resource: `clusterrolebindings`; name: `cluster-admin`; subresource: `None`; status: `201`.
   - К чему привело: ServiceAccount `monitoring` был привязан к ClusterRole `cluster-admin` через RoleBinding `escalate-binding`.

5. Удаление audit-policy:
   - Кто: `system:node:minikube`; verb: `create`; namespace: `kube-system`; resource: `pods`; name: `kube-apiserver-minikube`; subresource: `None`; status: `403`.
   - Возможные последствия: удаление или изменение audit policy снижает наблюдаемость кластера и может скрыть дальнейшие действия атакующего.


## Вывод

В audit.log найдены признаки инцидента: попытка доступа к Secret, создание privileged Pod, exec в системный Pod, удаление объекта audit-policy и создание RoleBinding с `cluster-admin`.

Даже если часть событий завершилась ошибкой `403`, они важны как индикаторы попытки несанкционированного доступа.
