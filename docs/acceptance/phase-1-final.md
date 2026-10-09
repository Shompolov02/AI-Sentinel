# Финальная приёмка Фазы 1 — issue #29

Дата: 2026-10-09 (Europe/Moscow). Проверенный коммит с исправлением и тестом:
`2a2ccb444b95887cd4f82e4d7974db2ecf19e231`. База: `main` на
`ed2c7bce54fba12b563709762eeec7138e5d75c6` (PR #40 слит).
Проверка проведена на чистом checkout этого коммита под macOS arm64,
Docker Engine 29.2.0, Compose v5.0.2, `uv` 0.12.17 и Python 3.11.4 в
workspace-окружении. Локальная `.env` получена копированием `.env.example`
и не включена в Git. Локальные отчёты сканеров и полный вывод gate лежат
в игнорируемой `.artifacts/`; они пересоздаются командами ниже.

## Воспроизведение

Из корня чистого checkout:

```sh
cp .env.example .env
make bootstrap
docker compose -p aisentinel29-manual -f deploy/docker-compose.yml config --quiet
docker compose -p aisentinel29-manual -f deploy/docker-compose.yml build
docker compose -p aisentinel29-manual -f deploy/docker-compose.yml up -d --wait
docker compose -p aisentinel29-manual -f deploy/docker-compose.yml ps
# Выполнить loopback HTTP-примеры и просмотр журналов из runbook.
docker compose -p aisentinel29-manual -f deploy/docker-compose.yml down
make test
make test-runtime
make acceptance
docker compose -p aisentinel29-manual -f deploy/docker-compose.yml down -v
git diff --check
```

`-p aisentinel29-manual` изолирует ручной стенд от других Compose projects.
Перед `make test-runtime` и `make acceptance` он остановлен, иначе их
подсети конфликтуют. `down -v` удаляет **только** volumes этого project;
использовать его для другого project без проверки имени нельзя. При проверке
на этой машине `UV_CACHE_DIR=.artifacts/uv-cache` размещал кэш внутри
проекта, `UV_OFFLINE=1` использовал уже установленные зависимости, а
`AI_SENTINEL_RUNTIME_REUSE_IMAGES=1` повторно использовал собранные образы.
Эти ускорители не меняют критерии. Если Docker CLI или Engine недоступен,
`make test-runtime` и `make acceptance` завершаются ошибкой.

## Результат обязательных команд

| Команда | Фактический результат |
| --- | --- |
| `docker compose -f deploy/docker-compose.yml config --quiet` | Код 0. |
| `docker compose -p aisentinel29-manual -f deploy/docker-compose.yml up -d --wait` и `ps` | Код 0; `target-app`, `nginx`, `http-ingress`, `cowrie`, `cowrie-ingress` — `healthy`. Только ingress публикуют `127.0.0.1:8080/2222/2223`. |
| `make test` | Код 0 на подготовительном прогоне: 63 passed, 1 skip из-за sandbox-доступа к Docker. Этот прогон **не** засчитан как итоговый. |
| `make acceptance` на проверенном коммите | Код 0: 64 обычных теста passed, 14 runtime-тестов passed, обязательных skip нет; Ruff, mypy, Semgrep, pip-audit, Gitleaks, Security Exceptions, Trivy и SBOM прошли. |
| `git diff --check` на проверенном коммите | Код 0, вывод пустой. |

`pip-audit` сообщил `No known vulnerabilities found` для 36 зависимостей.
Trivy создал `trivy-fs.json`, `trivy-config.json` и `trivy-image.json` без
HIGH/CRITICAL результатов по текущей policy. SBOM — CycloneDX 1.7,
108 компонентов. Gitleaks сообщил `no leaks found`. SARIF Semgrep содержит
две `inSource`-подавленные находки `shell=True` в преднамеренно уязвимой
лабораторной поверхности; **неподавленных находок — 0**. Их граница и
компенсирующие меры записаны в
[`issue-23-target-app-injection.yaml`](../security/exceptions/issue-23-target-app-injection.yaml),
а срок записи проверяет `make security-exceptions`. Одноразовых ручных
пропусков gate не применялось.

## Матрица 22 критериев интервью

Нумерация соответствует [пунктам 1–22](../spec/phase-1-interview-notes.md#вопрос-18-финальные-acceptance-criteria).
Тесты ниже находятся в
[`test_nginx_edge_runtime.py`](../../tests/integration/test_nginx_edge_runtime.py),
[`test_compose_policy.py`](../../tests/security/test_compose_policy.py) и
[`test_target_app.py`](../../tests/unit/test_target_app.py).
Каждая строка имеет воспроизводимую команду и наблюдаемый результат.

| № | Команда / проверка | Фактическое evidence |
| --- | --- | --- |
| 1 | `docker compose -f deploy/docker-compose.yml config --quiet` | Код 0; нормализованную модель также читает `make test`. |
| 2 | `up -d --wait`, `ps`; `make test-runtime` | Пять сервисов `healthy`; `test_all_services_are_healthy_and_only_ingress_has_host_ports` passed. |
| 3 | `curl --fail http://127.0.0.1:8080/health`; `make test-runtime` | HTTP 200, JSON `status=ok`; `test_published_edge_routes_http_and_rejects_unknown_host` passed. |
| 4 | `make test-runtime` | `test_cowrie_accepts_loopback_ssh_telnet_and_records_synthetic_logins` passed: SSH и Telnet доступны через loopback и фиксируют синтетические попытки входа. |
| 5 | `ps`; `make test` и `make test-runtime` | У `target-app` только внутренний `8000/tcp`; host mapping отсутствует в Compose policy и Docker inspect. |
| 6 | `make test-runtime` и `make test` | `test_nginx_cannot_resolve_or_reach_cowrie` подтверждает Nginx → Target App; policy закрепляет `prod_net` только за Nginx и Target App, а runtime-пробы исключают доступ Cowrie. |
| 7 | `make test` | `test_compose_has_only_the_accepted_services_and_network_attachments` passed: Target App только в `prod_net`, Cowrie только в `honeynet`. |
| 8 | `make test-runtime` | `test_honeynet_cannot_resolve_or_reach_http_zone` и `test_target_app_cannot_resolve_or_reach_honeynet` passed; DNS, TCP и маршруты проверены в обоих направлениях. |
| 9 | `make test-runtime` | `test_vulnerable_workloads_have_no_host_or_external_route` и `test_cowrie_has_no_route_to_prod_host_or_external_network` passed; пробы ограничены timeout и не зависят от доступности публичного сайта. |
| 10 | `make test-runtime` | `test_cowrie_accepts_loopback_ssh_telnet_and_records_synthetic_logins` читает raw JSON; `test_cowrie_hardening_and_named_volumes_survive_recreation` подтверждает сохранение `cowrie-logs`. |
| 11 | `make test-runtime` | `test_cowrie_hardening_and_named_volumes_survive_recreation` создаёт синтетический download marker и читает его после пересоздания из `cowrie-downloads`. |
| 12 | `docker compose ... exec -T nginx cat /var/log/nginx/access.log`; `make test-runtime` | JSON access log содержит `request_id=da1686f08c85c0fcabafba132066ca8a`; `test_http_logs_and_sqlite_survive_service_recreation` passed для `nginx-logs`. |
| 13 | `make test-runtime` | `test_http_logs_and_sqlite_survive_service_recreation` вставляет синтетическую SQLite-запись и находит её через API после пересоздания `target-app` в `target-app-data`. |
| 14 | `make test` и `make test-runtime` | `test_dashboard_contains_warning_and_interactive_forms` и HTTP runtime-проверка находят `LABORATORY ENVIRONMENT`. |
| 15 | `curl` к `/docs`, `/redoc`, `/openapi.json`; `make test-runtime` | Все три маршрута дали HTTP 200; `test_openapi_document_is_valid_and_lists_api_routes` проверил OpenAPI. |
| 16 | Три `curl`-примера из [runbook](../runbooks/phase-1-local-edge.md); `make test` | SQLi вернула 4 seed-записи, Command Injection вернула `vuln_verified`, Prompt Injection вернула `RECEIVED` и `PROMPT_INPUT_RECEIVED` в журнале; unit/API fixtures passed. Внешняя LLM не вызывается по `test_analyze_logs_untrusted_text_without_network_or_local_execution`. |
| 17 | `make test` и `make test-runtime` | Пройдены тесты 4096-символьного поля, 50 SQL-строк, 5-секундного timeout, 4 KiB вывода, безопасных JSON-ошибок и correlation ID. Новый `test_edge_accepts_body_below_two_mib_and_rejects_larger_body` прошёл: 1,5 MiB → 200, больше 2 MiB → 413. |
| 18 | `make test`; `make test-runtime` | Compose policy проверяет non-root UID, `read_only`, tmpfs и ресурсы; runtime inspect проверяет hardening Cowrie после пересоздания. |
| 19 | `make test` | `test_every_service_drops_privileges_and_has_no_host_escape` passed: нет privileged, host networking, Docker socket и `cap_add`; все capabilities сброшены. |
| 20 | `test -f .env.example && test -f docs/runbooks/phase-1-local-edge.md`; `make test` и `make test-runtime` | Файлы присутствуют; 64 обычных и 14 runtime-тестов прошли на итоговом кодовом коммите. |
| 21 | `git diff --check`; `make acceptance` | Оба кода 0; quality, Gitleaks, Trivy и остальные обязательные security-команды завершились успешно без инфраструктурного сбоя. |
| 22 | Последовательность из раздела «Воспроизведение» на чистом коммите | `bootstrap`, Compose config/build/up/ps/down, HTTP-примеры, `make test`, `make test-runtime`, `make acceptance` и `down -v` выполнены; итоговый gate не содержит обязательных skip. |

## Границы Фазы 1 и эксплуатационные замечания

Проверенная Compose model содержит только пять предусмотренных сервисов и
сетей, без `management_net`. В [runbook](../runbooks/phase-1-local-edge.md)
явно исключены K3s, Ansible, Fluent Bit, внешняя LLM, SOAR, TLS и
автоматизированный DAST runner. Ручные ZAP/Nikto примеры не являются частью
22 обязательных критериев; эти инструменты на проверочной машине не
установлены. Отсутствие Telnet CLI компенсировано обязательной автоматической
TCP/Telnet-пробой в runtime harness, которая прошла.

Первая попытка загрузить закреплённый Cowrie image дала TLS handshake
timeout Docker Hub. После загрузки того же digest через BuildKit повторный
`docker pull` прошёл, Compose запустил пять healthy контейнеров, и итоговый
`make acceptance` завершился с кодом 0. Таймаут не засчитан как успех.
