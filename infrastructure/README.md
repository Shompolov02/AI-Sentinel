# Infrastructure

Область декларативных и эксплуатационных шаблонов. На этом этапе здесь нет реальных сетей, подсетей, портов, секретов или production-развёртывания.

- `docker/` — Dockerfile и container baseline для нейтрального smoke-пакета;
- `compose/` — безопасный Compose-шаблон smoke-baseline без боевых интеграций;
- `ansible/` — будущая автоматизация стенда;
- `k8s/` — будущие Kubernetes/K3s-манифесты.

Smoke-baseline использует pinned multi-stage образ, непривилегированный UID
`10001`, read-only filesystem, `tmpfs` только для временных данных, dropped
capabilities и named network `sentinel_baseline`. Он не публикует порты и не
запускает Honeynet, Netfilter или другие привилегированные сервисы.

Проверка итоговой Compose-модели:

```text
docker compose -f infrastructure/compose/smoke.yaml config
```
