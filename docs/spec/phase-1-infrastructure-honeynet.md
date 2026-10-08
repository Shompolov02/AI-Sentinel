# Фаза 1: инфраструктура и Honeynet

Статус: утверждённая спецификация для декомпозиции и реализации.

## Problem Statement

Проекту AI-Sentinel (САЗИИ) нужен воспроизводимый локальный стенд, на котором можно безопасно исследовать входящий HTTP-трафик и взаимодействие с Honeynet до появления компонентов сбора, нормализации и анализа Событий безопасности. Без единой сетевой топологии, изолированных зон, контролируемых точек входа и проверок фактической изоляции преднамеренно уязвимый Target App и Cowrie могут стать доступными извне или использоваться для доступа к соседним сетям.

## Solution

Создать локальный Docker Compose стенд с двумя изолированными зонами: `prod_net` для HTTP Nginx и Target App и `honeynet` для Cowrie. Узкие HTTP и TCP ingress связывают эти зоны с отдельными host-facing сетями. По умолчанию публиковать HTTP, SSH и Telnet только на IPv4 loopback хоста. Закрепить минимальные права контейнеров, ограничить ресурсы, сохранить необходимые данные в named volumes, а сетевую изоляцию и основные сценарии проверять статическими и runtime-тестами.

Target App намеренно предоставляет контролируемые Command Injection, SQLi и Prompt Injection surfaces. Это лабораторная цель, не production-сервис. Target App не вызывает внешние LLM и не получает доступ к Honeynet или внешней сети.

## User Stories

1. Как разработчик стенда, я хочу запускать все компоненты локальным Docker Compose, чтобы воспроизводить лабораторную инфраструктуру без Kubernetes или удалённой среды.
2. Как оператор, я хочу, чтобы опубликованные порты по умолчанию слушали только `127.0.0.1`, чтобы случайно не выставить уязвимые сервисы в локальную сеть или интернет.
3. Как оператор изолированной лаборатории, я хочу параметризовать адрес публикации через `.env`, чтобы явно включать доступ с других интерфейсов только по осознанной процедуре из runbook.
4. Как разработчик, я хочу открывать Target App через HTTP-вход Nginx на порту 8080, чтобы внутренняя служба приложения не имела прямого host mapping.
5. Как исследователь безопасности, я хочу подключаться к SSH-ловушке Cowrie на порту 2222, чтобы проверять регистрацию попыток аутентификации и команд.
6. Как исследователь безопасности, я хочу подключаться к Telnet-ловушке Cowrie на порту 2223, чтобы проверять второй honeypot-протокол.
7. Как оператор, я хочу отделить Cowrie от Target App сетями Docker, чтобы атака на один компонент не давала сетевой путь к другому.
8. Как оператор, я хочу, чтобы HTTP Nginx подключался только к внутренним `prod_net` и `http_edge`, чтобы reverse proxy не имел прямого host-facing маршрута или пути в Honeynet.
9. Как владелец стенда, я хочу запрещать egress из сетей, чтобы скомпрометированные или намеренно уязвимые компоненты не атаковали внешние цели.
10. Как разработчик, я хочу иметь синтетический каталог активов и SQLi surface, чтобы безопасно демонстрировать и тестировать инъекцию без реальных данных.
11. Как исследователь, я хочу иметь ограниченный Command Injection surface, чтобы воспроизводить сценарии выполнения команд с timeout и ограниченным объёмом результата.
12. Как исследователь Prompt Injection, я хочу отправлять недоверенный текст в API анализа и видеть событие его приёма, чтобы готовить сценарии будущей фазы без внешней LLM.
13. Как оператор, я хочу видеть заметное предупреждение `LABORATORY ENVIRONMENT — INTENTIONALLY VULNERABLE TARGET`, чтобы не принять Target App за продуктивный сервис.
14. Как тестировщик, я хочу получать предсказуемые JSON-ошибки без stack trace и путей хоста, чтобы проверять API без утечки внутренней информации.
15. Как оператор, я хочу просматривать структурированные логи Nginx, Target App и Cowrie через Docker logs/volumes, чтобы исследовать сырую телеметрию без внешних систем сбора.
16. Как разработчик, я хочу связывать запрос, ответ и запись лога по correlation ID, чтобы прослеживать лабораторный HTTP-запрос.
17. Как оператор, я хочу сохранять SQLite, Cowrie logs/downloads и Nginx logs в named volumes, чтобы данные переживали перезапуски контейнеров.
18. Как инженер качества, я хочу проверять Compose policy автоматически, чтобы топология и security baseline не деградировали незаметно.
19. Как инженер качества, я хочу проверять сетевые ограничения runtime-пробами с коротким timeout, чтобы подтвердить фактическую изоляцию, а не только декларации YAML.
20. Как разработчик, я хочу запускать полный набор unit, integration и security policy checks воспроизводимыми командами, чтобы проверять изменения локально и в CI.
21. Как оператор, я хочу иметь runbook запуска, проверки, просмотра логов и удаления volumes, чтобы управлять стендом без ручного восстановления неописанных шагов.
22. Как владелец проекта, я хочу иметь явные acceptance criteria, чтобы Фаза 1 считалась готовой только после проверки функциональности, изоляции и документации.

## Implementation Decisions

- Платформа только локальный Docker Compose. K3s и Ansible не входят в Фазу 1.
- Сервисы: HTTP Nginx, Target App (FastAPI), Cowrie, отдельный HTTP ingress и TCP ingress для SSH/Telnet. `management_net`, Fluent Bit и нормализация Событий безопасности относятся к следующей фазе.
- Сети: внутренние `prod_net` (Nginx и Target App), `honeynet` (Cowrie и TCP ingress) и `http_edge` (Nginx и HTTP ingress) используют изолированный IPv4 gateway. Host-facing `http_ingress` и `cowrie_ingress` содержат только соответствующие ingress-сервисы. Target App подключён только к `prod_net`, Cowrie — только к `honeynet`. Используются только IPv4 CIDR; IPv6 отключается на Compose bridge. Контейнеры не используют `network_mode: host`.
- Топология входа:

  ```text
  127.0.0.1:8080 -> HTTP ingress -> http_edge -> nginx -> prod_net -> target-app:8000
  127.0.0.1:2222 -> TCP ingress -> honeynet -> cowrie:2222
  127.0.0.1:2223 -> TCP ingress -> honeynet -> cowrie:2223
  ```

- Публикуются только HTTP `8080/tcp`, SSH `2222/tcp` и Telnet `2223/tcp`, через `${BIND_ADDRESS}` с default `127.0.0.1`. Nginx, Target App и Cowrie не имеют `ports`; HTTP публикует только HTTP ingress, SSH/Telnet — только TCP ingress. TLS и host port 22 не используются. Режим `0.0.0.0` допустим только для изолированной лаборатории и сопровождается заметным предупреждением в runbook.
- Основной Compose-манифест должен иметь один канонический путь в `deploy/` или `infrastructure/compose/`; допустим корневой симлинк. Выбранное имя и путь должны быть единообразно отражены в документации и тестовых командах.
- Egress deny-by-default. У Cowrie нет пути в production-like, host или внешние сети. Target App не требует внешних зависимостей и не имеет egress. `internal: true` считается декларативной частью контроля, но не доказательством изоляции: требуется runtime-проверка.
- HTTP Nginx выполняет только reverse proxy на `target-app:8000` и не подключается к Honeynet. HTTP ingress передаёт TCP-поток с PROXY protocol на Nginx; основной Nginx доверяет наблюдаемому ingress-адресу только из `http_edge`. Отдельный TCP ingress использует Nginx stream только для `cowrie:2222/2223`; он не подключается к `prod_net`. Неизвестный HTTP Host обрабатывается отдельным default server (ответ `444` или `400`); основной server разрешает `localhost`, `127.0.0.1` и `${SERVER_NAME:-localhost}`.
- Nginx генерирует новый `$request_id` для каждого запроса, перезаписывает клиентский `X-Request-ID` и передаёт собственное значение Target App. Target App возвращает correlation ID в response header и response body, если это совместимо с контрактом конкретного endpoint, и включает ID в JSON-логи. Пересылка client IP и доверие к forwarded headers должны быть явно ограничены Nginx; произвольным клиентским forwarded headers доверять нельзя.
- Nginx и Target App запускаются non-root. Для обоих: `cap_drop: [ALL]`, `no-new-privileges: true`, отсутствие `privileged`, Docker socket и host networking. Target App использует UID `10001`; Nginx — встроенного unprivileged-пользователя выбранного образа.
- Resource limits: Nginx `cpus: "0.25"`, `mem_limit: 128m`, `pids_limit: 50`; Target App `cpus: "0.5"`, `mem_limit: 512m`, `pids_limit: 100`.
- Target App имеет `read_only: true`, `/tmp` на `tmpfs` с `rw,noexec,nosuid,size=64m`, SQLite в named volume `target-app-data`, application logs только stdout/stderr.
- Cowrie хранит raw JSON logs в `cowrie-logs` и загруженные файлы в `cowrie-downloads`. Nginx access logs формируются в JSON и сохраняются в `nginx-logs`. Target App пишет структурированные JSON logs в stdout: timestamp, level, correlation ID, client IP, method, path, status и duration. Stack trace в application logs не выводится.
- Входные `target`, `query` и `text` ограничиваются 4096 символами. SQL выдача ограничивается 50 строками. Command Injection endpoint ограничивает время выполнения 5 секундами и stdout/stderr суммарно 4 KiB. Ошибки не раскрывают stack trace, секреты или чувствительные пути хоста.
- Target App содержит dashboard на Jinja2 и локальном CSS/JS без внешних CDN. Обязательны формы диагностики, поиска активов и `AI Security Feedback / Log Analysis`; доступны `/docs`, `/redoc`, `/openapi.json` и `/health`. CSP: `default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'`; также `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- SQLi surface: `GET /search?q=...` и `POST /api/search`; таблица `assets` содержит синтетические `id`, `hostname`, `ip_address`, `status`, `description`. Prompt Injection surface — `POST /api/analyze` с JSON-полем `text`; вход валидируется и логируется событием `PROMPT_INPUT_RECEIVED`, status `RECEIVED`. Внешние и локальные LLM не вызываются.
- Контролируемый Command Injection endpoint принимает лабораторную цель, выполняет ping и возвращает ограниченный stdout/stderr. Он не должен быть доступен из Honeynet или извне в обход Nginx.
- Cowrie image tag/digest должен быть pinned до реализации. Выбранный образ проверяется на совместимость с read-only rootfs, writable paths, non-root и согласованными security options; точный pin пока не утвержден в интервью и должен быть оформлен как implementation decision до merge.
- Healthchecks: Cowrie TCP `2222` и `2223`; Target App `GET /health` внутри `prod_net`; Nginx проверяет проксируемый `/health` через отдельный loopback listener; HTTP ingress проверяет опубликованный `/health`, TCP ingress проверяет конфигурацию без создания фиктивных сессий Cowrie. Используется `depends_on: condition: service_healthy`. Все сервисы имеют `restart: unless-stopped`.
- Статические Pytest policy checks читают нормализованную Compose-конфигурацию и проверяют сети и их состав, публикацию портов и default binding, отсутствие прямого порта Target App, `internal: true`, IPv4 CIDR, non-root, capabilities, resource limits, healthchecks, Docker socket, privileged и host networking.
- Runtime integration checks проверяют обе стороны изоляции: Cowrie не разрешает Target App/Nginx и не достигает IP `prod_net`; Target App не разрешает Cowrie и не достигает Honeynet портов/подсети. Проверяются DNS-имена и IP адреса. Каждая probe ограничена timeout 2 секунды. Для egress проверки не используются нестабильные публичные endpoints как единственный oracle.
- Если в целевых образах отсутствуют инструменты probes, runtime harness может использовать одноразовый тестовый контейнер, подключённый к проверяемой сети, без изменения Cowrie/Target App образа. Приёмочный тест обязан доказать фактическую недоступность соседних и внешних маршрутов; сам механизм harness документируется и не расширяет capabilities сервисов.
- Функциональные тесты проверяют UI и warning badge, OpenAPI endpoints, health, ограничения полей/body, SQLi и Command Injection fixtures, Prompt Injection logging, отсутствие вызова LLM, отсутствие утечки stack trace/host paths. Controlled fixtures: SQLi `' OR '1'='1` возвращает все seed-записи; Command Injection `127.0.0.1; echo "vuln_verified"` подтверждает строку `vuln_verified` и завершается не более чем за 5 секунд.
- DAST runner не автоматизируется в этой фазе. Runbook содержит примеры ручного запуска ZAP/Nikto; OpenAPI schema валидируется автоматизированно.
- Используются только synthetic данные и credentials. `.env` не коммитится; `.env.example` содержит безопасные значения. Gitleaks/Trivy или существующий согласованный security scanner проверяет Compose и fixtures на секреты и известные уязвимости. Логи не отправляются во внешние системы; log rotation, backup/restore и формальная retention policy не входят в Фазу 1.
- Runbook включает конфигурационную проверку Compose, сборку/запуск, статус, просмотр логов, URL UI, SSH/Telnet подключение, запуск тестов, ручные DAST примеры и безопасный teardown `down` / `down -v`.

## Testing Decisions

- Тесты проверяют наблюдаемое поведение интерфейсов и сетей, а не только внутреннюю реализацию. Статическая проверка YAML не заменяет runtime probe, а runtime-проверка не заменяет проверку policy-манифеста.
- Высший общий seam — команда качества проекта, вызывающая форматирование/lint/type checks, Pytest, Compose config validation и security policy checks; конкретное имя команды согласуется с существующим quality interface Фазы 0.
- Pytest unit/API tests покрывают Target App endpoints, UI markers, OpenAPI, health, ограничения ввода/вывода, корреляцию, SQLi fixture, Command Injection timeout/output, Prompt Injection event logging и безопасные ошибки.
- Pytest policy tests проверяют `docker compose config` normalized output: точный набор сетей, service attachments, host bindings, container hardening, ресурсы, healthchecks, volumes и запрет опасных конфигураций.
- Docker runtime integration tests поднимают стенд и проверяют доступность HTTP/SSH/Telnet с loopback, отсутствие прямого host mapping для Target App, двунаправленную сетевую изоляцию и egress. Сетевые probes завершаются не позднее 2 секунд и сообщают диагностику при неожиданной доступности.
- Сканирование секретов и контейнерной конфигурации проверяет Compose, fixtures и безопасный example env. Проверки Trivy не должны считаться успешными при недоступности базы сканера; политика severity следует базовой security policy репозитория.
- Acceptance проверяется на чистом checkout командами, перечисленными в runbook. Минимальная приемка: Compose config, все healthchecks, протоколы/порты, volumes/logging, API/UI, security baseline, runtime isolation, quality gate и security scans.
- Prior art для Docker runtime и бизнес-тестов следует зафиксировать при реализации по существующей Фазе 0 и тестовой структуре репозитория; если аналогичных интеграционных seam ещё нет, тест harness вводится как один общий управляемый интерфейс, а не как набор разрозненных shell probes.

## Out of Scope

- K3s, Kubernetes, Ansible и удалённое/production развертывание.
- Fluent Bit, management network, сбор и нормализация Событий безопасности, единый event contract.
- AI Agent Core, Prompt Guard, LLM Client, внешняя LLM/Ollama, Triage Engine, SOAR, DefectDojo и Firewall Enforcer.
- Реальная блокировка атак, host firewall management, Docker socket access и host-level capabilities.
- Production security для преднамеренно уязвимого Target App; он предназначен только для изолированной лаборатории.
- TLS, mTLS, production identity/RBAC и публикация в registry.
- Автоматизированные ZAP/Nikto scans и CI DAST runner; только ручные инструкции в runbook.
- Лог-агрегация во внешние сервисы, retention/rotation policy, backup/restore и RPO/RTO.
- Поддержка IPv6.

## Further Notes

- Канонические термины и ограничения задаются `CONTEXT.md`; Target App и Honeynet нельзя описывать как production-компоненты.
- Источник требований интервью — `docs/spec/phase-1-interview-notes.md`; критерии приемки состоят из 22 пунктов, указанных там.
- Решения Issue #19 зафиксированы в `docs/architecture/decisions/phase-1-runtime-baseline.md`: канонический Compose path `deploy/docker-compose.yml`, immutable Cowrie digest, поведение `/health` и неизвестного Host (`444`), JSON error contract, обработка `X-Request-ID` и локальный Pytest/Docker CLI harness.
- Топология и проверки отсутствия egress из Issue #27 зафиксированы в `docs/architecture/decisions/phase-1-runtime-isolation.md`; этот ADR уточняет исторические схемы с четырьмя сервисами.
- Network isolation тесты должны исполняться на поддерживаемых локальных Docker окружениях. Для сетевой модели `internal: true` нельзя заявлять запрет доступа к хосту только на основании статической конфигурации; нужные направления подтверждаются runtime.
- Публикация с `BIND_ADDRESS=0.0.0.0` существенно меняет риск-профиль. Она допустима только на отдельной изолированной сети, с явным операторским решением и проверкой адреса перед запуском.
