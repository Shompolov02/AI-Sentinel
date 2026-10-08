# Фаза 1: протокол технического интервью

Исторические решения о двух/трёх сетях и прямой публикации HTTP Nginx
уточнены ADR для Issue #25 и #27. Текущая топология и граница egress описаны
в `docs/architecture/decisions/phase-1-runtime-isolation.md`.

Статус: рабочая запись требований и архитектурных решений.

Документ фиксирует ответы на интервью по подготовке Фазы 1: «Развертывание сетевой инфраструктуры, сетевой изоляции и Honeynet-стенда». Он сохраняет принятые решения до подготовки итоговой спецификации. Нерешённые вопросы помечены явно и не должны превращаться в неявные требования.

## Контекст интервью

- Проект: AI-Sentinel (САЗИИ).
- Фаза: 1.
- Базовая платформа: локальный Docker Compose.
- K3s и Ansible: строго вне scope Фазы 1; могут рассматриваться позже при масштабировании.
- Нормализованный контракт События безопасности и Fluent Bit: Фаза 2, не фиксируются этим протоколом.
- Target App: преднамеренно уязвимое тестовое приложение, не продуктивный бизнес-сервис.
- Все уязвимости и внешние порты предназначены только для контролируемого лабораторного стенда.

## Блок 1. Топология и модель развертывания

### Вопрос 1. Целевая платформа Фазы 1

**Вопрос:** где должен запускаться стенд?

**Решение:** использовать только локальный Docker Compose. K3s и Ansible не входят в Фазу 1 и будут рассмотрены отдельно при масштабировании.

### Вопрос 2. Назначение и режим доступа

**Вопрос:** для какого режима предназначен стенд?

**Решение:** по умолчанию это безопасный локальный/лабораторный стенд разработчика. Порты по умолчанию биндятся на `127.0.0.1`, чтобы исключить случайное сканирование из локальной сети или интернета во время отладки.

Публикация на `0.0.0.0` допускается как параметризуемая опция через `.env` для этапа симуляции атак. Конкретный механизм безопасного включения этого режима и предупреждения оператора должен быть описан в итоговой спецификации и runbook.

### Вопрос 3. Внешний сетевой периметр и порты

**Вопрос:** какие точки входа публикуются на хосте?

**Решение:**

- `BIND_ADDRESS:8080/tcp` — HTTP-вход Nginx к Target App; используется непривилегированный порт хоста.
- `BIND_ADDRESS:2222/tcp` — SSH Cowrie.
- `BIND_ADDRESS:2223/tcp` — Telnet Cowrie.
- TLS в Фазе 1 не используется.
- Порт хоста `22` не используется, чтобы не конфликтовать с SSH хостовой машины.
- Прямой доступ к контейнерам в обход определённых входных точек запрещён.

Внутренние порты Target App наружу не выставляются.

### Вопрос 4. Роль Nginx

**Вопрос:** должен ли Nginx проксировать также SSH/Telnet?

**Решение:** нет. Nginx выполняет только L7 HTTP reverse proxy и подключён только к `prod_net`.

- Nginx проксирует HTTP-трафик на `target-app:8000`.
- После уточнения в Issue #25 Cowrie остаётся только в `honeynet`, а host
  mapping публикует отдельный TCP ingress:
  - `127.0.0.1:2222 -> cowrie-ingress -> cowrie:2222/tcp`;
  - `127.0.0.1:2223 -> cowrie-ingress -> cowrie:2223/tcp`.
- Nginx не подключается к `honeynet`.
- HTTP Nginx не служит мостом между `prod_net` и `honeynet`; отдельный TCP
  ingress принимает только SSH/Telnet и не подключён к `prod_net`.

### Вопрос 5. Сетевая схема

**Вопрос:** какие сети и сервисы входят в топологию?

**Решение:**

```text
Host localhost
   |
   +-- 8080 -> nginx -- prod_net -- target-app:8000
   |
   +-- 2222 -> cowrie-ingress -- honeynet -> cowrie:2222
   +-- 2223 -> cowrie-ingress -- honeynet -> cowrie:2223
```

- `prod_net` содержит только Nginx и Target App.
- `honeynet` содержит Cowrie и ограниченный TCP ingress; Cowrie подключён
  только к этой сети.
- `cowrie_ingress` содержит только TCP ingress и обеспечивает публикацию host
  портов на Docker Engine, где internal-only сеть их не публикует.
- `management_net` в Фазе 1 не создаётся; он может появиться в Фазе 2 вместе с Fluent Bit.
- Контейнеры не используют `network_mode: host`.
- Docker socket никуда не монтируется.
- Target App и Cowrie не имеют прямого сетевого доступа друг к другу.

### Вопрос 6. Политика исходящего трафика

**Вопрос:** какие исходящие соединения разрешены?

**Решение:** применяется deny-by-default политика.

- Для `honeynet` запрещён исходящий трафик во внешние и локальные сети хоста. Сеть должна быть настроена как `internal: true` либо дополнительно защищена эквивалентным контролем фактического внешнего роутинга.
- Для `prod_net` внешний egress также заблокирован или ограничен до отсутствия необходимых зависимостей.
- Cowrie не должен использоваться как плацдарм для атак на внешние цели.
- Target App не требует внешних зависимостей в Фазе 1.

`internal: true` рассматривается как часть Docker-конфигурации, но acceptance-тест должен проверять фактическую недоступность внешних и соседних сетей, а не только наличие флага.

### Вопрос 7. Адресный план

**Вопрос:** какие CIDR использовать?

**Решение:** адресный план выносится в `.env.example` и имеет следующие значения по умолчанию:

```text
PROD_NET_SUBNET=172.30.10.0/24
HONEYNET_SUBNET=172.30.20.0/24
```

Имя сети канонически `prod_net`; упоминание `rod_net` в ответе на интервью является опечаткой.

Необходимо предусмотреть проверку конфликта с локальными сетями Docker/VPN при подготовке Compose-конфигурации или runbook.

### Вопрос 8. Административный доступ и отладка

**Вопрос:** как обращаться к сервисам?

**Решение:** доступ к стенду выполняется только через localhost-порты и Docker Compose tooling.

- Target App доступен через Nginx.
- Cowrie доступен через localhost-порты `2222` и `2223`.
- Swagger UI (`/docs`) и ReDoc (`/redoc`) остаются включёнными для DAST и демонстрации API.
- Внутренние порты сервисов напрямую на host interface не публикуются, кроме перечисленных входных mappings.

### Вопрос 9. Профили Compose

**Вопрос:** нужны ли отдельные Compose-профили?

**Решение:** в Фазе 1 используется один профиль/один основной стенд без усложнения профилями. Изменяемые параметры, включая `BIND_ADDRESS`, задаются через `.env`.

### Вопрос 10. Definition of Done Фазы 1

**Вопрос:** что входит в границу готовности?

**Решение:** Фаза 1 считается готовой при наличии:

1. воспроизводимого Docker Compose-стенда с non-root контейнерами;
2. раздельных `prod_net` и `honeynet` с отдельным TCP ingress на
   `cowrie_ingress`;
3. Nginx-шлюза перед Target App;
4. Cowrie с raw JSON-логами в примонтированный том;
5. FastAPI Target App с Jinja2/CSS UI и поверхностями Command Injection, SQLi и Prompt Injection;
6. автоматизированного теста сетевой изоляции;
7. runbook запуска и остановки стенда.

## Блок 2. Cowrie, Nginx и Target App

### Вопрос 1. Образ и поставка Cowrie

**Вопрос:** использовать готовый или собственный образ?

**Решение:** использовать официальный проверенный образ Cowrie с зафиксированным version tag или pinned SHA. В качестве обсуждавшихся примеров указаны `cowrie/cowrie:v2.5.0` и digest-pinned образ; floating tag `latest` не является финальным вариантом воспроизводимой поставки.

Официальный контейнер ожидается запускаемым от непривилегированного пользователя `cowrie` (UID 1000). Собственный wrapper не требуется, если выбранный pinned образ действительно поддерживает этот режим.

### Вопрос 2. Внутренние порты Cowrie

**Вопрос:** какие протоколы и порты поддерживаются?

**Решение:** только TCP и IPv4:

- SSH: `cowrie:2222/tcp`;
- Telnet: `cowrie:2223/tcp`.

IPv6 в Compose не используется/отключается.

### Вопрос 3. Учётные данные Cowrie

**Вопрос:** какой режим synthetic credentials нужен?

**Решение:** сохраняется upstream-поведение по умолчанию с возможностью демонстрации распространённых synthetic credentials, включая варианты вроде `root/root`, `admin/admin`, `ubuntu/ubuntu`, а также любые комбинации, которые допускает выбранная конфигурация Cowrie.

Реальные пароли и секреты не используются.

### Вопрос 4. Persistence Cowrie

**Вопрос:** какие данные сохранять?

**Решение:** создаются два named volume:

- `cowrie-logs` -> `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`;
- `cowrie-downloads` -> `/cowrie/cowrie-git/var/lib/cowrie/downloads`.

`docker compose down` сохраняет volumes. Для полного удаления данных используется `docker compose down -v`. Сложная retention-policy в Фазе 1 не вводится.

### Вопрос 5. Формат JSON-логов

**Вопрос:** нормализовать ли Cowrie logs уже в Фазе 1?

**Решение:** сохранять исходный raw JSON event log Cowrie без дополнительной нормализации. Логи содержат попытки входа, команды и timestamps. Нормализация и маппинг в единый контракт событий относятся к Фазе 2 вместе с Fluent Bit.

Redaction в Фазе 1 не выполняется, поскольку ловушка и credentials синтетические. Raw logs всё равно считаются недоверенными данными и не должны попадать в LLM или управляющий контур без будущих защитных стадий.

### Вопрос 6. Healthcheck Cowrie

**Вопрос:** как проверять готовность ловушки?

**Решение:** использовать лёгкий TCP-connect к портам `2222` и `2223` без интерактивного входа. Healthcheck не должен создавать ложные события сессий и брутфорса.

### Вопрос 7. Security baseline Cowrie

**Вопрос:** какие ограничения контейнера обязательны?

**Решение:**

- запуск от non-root пользователя `cowrie`;
- `cap_drop: [ALL]`;
- `no-new-privileges: true`;
- `mem_limit: 512m` или эквивалентное ограничение памяти;
- `cpus: 0.5` или эквивалентное ограничение CPU;
- `pids_limit: 100`;
- отсутствие `privileged: true`;
- отсутствие Docker socket;
- отсутствие host networking.

`read_only`, tmpfs и точные writable paths требуют проверки совместимости с pinned-образом Cowrie и будут зафиксированы при реализации Compose. Если образ не поддерживает требуемый non-root режим, выбор образа должен быть пересмотрен; небезопасное молчаливое ослабление baseline недопустимо.

### Вопрос 8. HTTP-маршрутизация Nginx

**Вопрос:** как Nginx обращается к Target App?

**Решение:** Nginx проксирует запросы на `target-app:8000`.

- Разрешаются стандартные REST-методы: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`.
- `client_max_body_size 2M`.
- `proxy_connect_timeout 5s`.
- `proxy_read_timeout 10s`.
- Rate limiting в Фазе 1 не включается, чтобы не мешать DAST и исследовательским тестам.
- `/docs`, `/redoc` и OpenAPI endpoint доступны через прокси.

Требования к WebSocket, chunked requests и поведению неизвестного `Host` ещё не согласованы и должны быть закрыты в Блоке 3 или итоговой спецификации.

### Вопрос 9. Nginx access logs

**Вопрос:** какой формат логов Nginx использовать?

**Решение:**

- `access.log` пишется в JSON в named volume `nginx-logs`;
- `error.log` остаётся в стандартном текстовом формате.

Минимальные поля JSON access log:

```text
time_iso8601
remote_addr
request_method
request_uri
status
body_bytes_sent
request_time
http_user_agent
http_x_forwarded_for
```

### Вопрос 10. Forwarded headers

**Вопрос:** как обрабатывать клиентские forwarded headers?

**Решение:** Nginx устанавливает значения сам:

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Входящие заголовки клиента не считаются доверенными. Необходимость явного очищения/перезаписи цепочки `X-Forwarded-For` и точный набор trusted proxy ranges требуют отдельного решения в Блоке 3.

### Вопрос 11. Хранилище и SQLi

**Вопрос:** какое хранилище используется для SQL injection surface?

**Решение:** SQLite, файл базы данных в named volume `target-app-data`.

SQLi всегда включена как намеренная лабораторная поверхность. Поиск реализуется через классическую конкатенацию сырых строк, например:

```python
f"SELECT * FROM assets WHERE hostname LIKE '%{query}%'"
```

Конкретный код должен быть ограничен синтетическими данными и лимитом результатов; surface не является шаблоном для обычного production-кода.

### Вопрос 12. Command Injection

**Вопрос:** где разместить Command Injection?

**Решение:**

- `POST /api/diagnostics/ping`;
- параметр `target` принимает IP или hostname;
- UI содержит форму, использующую тот же endpoint;
- команда строится как намеренно уязвимый вызов `ping -c 2 {target}` через `subprocess` с `shell=True`.

Ограничения поверхности:

- процесс выполняется внутри Target App-контейнера;
- Target App запускается от UID `10001`;
- timeout процесса: `5` секунд;
- суммарный stdout/stderr ограничивается `4 KiB`;
- результат возвращается в UI и API;
- Docker socket, host network и дополнительные capabilities отсутствуют.

Уязвимость намеренная и допустима только в локальном/лабораторном стенде. Контейнерные ограничения не превращают endpoint в безопасный production-интерфейс.

### Вопрос 13. SQLi surface

**Вопрос:** какой пользовательский сценарий демонстрирует SQLi?

**Решение:** поиск по каталогу сетевых активов/серверов компании:

- `GET /search?q=...`;
- `POST /api/search`.

Используется таблица `assets` с полями:

```text
id, hostname, ip_address, status, description
```

Данные исключительно синтетические, например `srv-database-01`, `10.0.0.15`, `production core`. SQL-выборка ограничивается максимум 50 записями.

### Вопрос 14. Prompt Injection surface

**Вопрос:** где разместить поверхность Prompt Injection?

**Решение:** UI-форма `AI Security Feedback / Log Analysis` и `POST /api/analyze` с JSON-телом:

```json
{"text": "untrusted security event or attacker supplied text"}
```

В Фазе 1 endpoint валидирует JSON и записывает входящий `text` в лог приложения со статусом `RECEIVED`. Он не вызывает внешнюю LLM, не содержит активной защиты и не исполняет введённый текст. Это surface для будущих тестов и исследований; Prompt Guard относится к следующей фазе.

### Вопрос 15. UI Target App

**Вопрос:** каким должен быть пользовательский интерфейс?

**Решение:** тёмный SOC/Security Dashboard на чистом Jinja2 и лёгком CSS без тяжёлого Node.js/React-фреймворка.

UI должен включать:

- dashboard со статусом стенда;
- форму сетевой диагностики;
- форму поиска по assets;
- форму `AI Security Feedback / Log Analysis`;
- отображение результатов операций;
- доступные `/docs` и `/redoc`.

В шапке размещается заметный бейдж:

```text
LABORATORY ENVIRONMENT — INTENTIONALLY VULNERABLE TARGET
```

### Вопрос 16. Ошибки и ограничения запросов

**Вопрос:** как отвечать на ошибки и ограничивать ввод?

**Решение:** возвращать информативные JSON-ошибки для исследователя и DAST:

- `400 Bad Request` для невалидного пользовательского ввода;
- `500 Internal Server Error` с кратким описанием причины;
- stack trace, секреты и чувствительные пути хоста не раскрывать;
- текстовые поля ограничить `4096` символами;
- SQL-результаты ограничить 50 записями.

Конкретный контракт ошибок, поля ответов и требования к сохранению результатов атак будут закрыты в Блоке 3.

### Вопрос 17. Прямой доступ и сетевой тест

**Вопрос:** как проверять сетевую изоляцию?

**Решение:**

- `target-app` не имеет директивы `ports`;
- Target App доступен только внутри `prod_net` через Nginx;
- Cowrie подключён только к `honeynet`;
- Nginx подключён только к `prod_net`;
- попытка из Cowrie обратиться к Target App или Nginx должна быть недоступна;
- результат проверки должен быть DNS failure или connection timeout с ограничением не более 2 секунд.

Изоляция проверяется автоматизированным тестом по фактическому поведению, а не только по декларации Compose.

## Блок 3. Security controls Compose, тестирование и acceptance criteria

### Вопрос 1. Security baseline Nginx и Target App

**Вопрос:** какие ограничения контейнеров обязательны?

**Решение:** для Nginx и Target App обязательны non-root, `cap_drop: [ALL]`, `no-new-privileges: true`, отсутствие `privileged`, host networking и Docker socket. Target App запускается с явным UID `10001`; Nginx использует встроенного непривилегированного пользователя образа.

Ресурсные лимиты:

- Nginx: `cpus: "0.25"`, `mem_limit: 128m`, `pids_limit: 50`;
- Target App: `cpus: "0.5"`, `mem_limit: 512m`, `pids_limit: 100`.

### Вопрос 2. Read-only filesystem

**Вопрос:** где сервисы могут писать данные?

**Решение:** Target App использует `read_only: true`. `/tmp` монтируется как `tmpfs` с параметрами `rw,noexec,nosuid,size=64m`. SQLite хранится в named volume `target-app-data`. Application logs пишутся в stdout/stderr.

### Вопрос 3. Логи Target App

**Вопрос:** какой формат логов приложения использовать?

**Решение:** структурированные JSON-логи в stdout. Минимальные поля: `timestamp`, `level`, `correlation_id`, `client_ip`, `method`, `path`, `status`, `duration_ms`.

При получении Prompt Injection записывается событие `PROMPT_INPUT_RECEIVED` со статусом `RECEIVED`. Поля `target`, `query` и `text` ограничиваются 4096 символами. Stack trace в логи не попадает.

### Вопрос 4. Correlation ID

**Вопрос:** кто генерирует correlation ID?

**Решение:** Nginx всегда генерирует новый UUID через `$request_id` для каждого запроса и передаёт его Target App в `X-Request-ID`. Target App возвращает его в заголовке/теле ответа и включает в JSON-логи. Клиентский correlation ID не принимается, что исключает спуфинг.

### Вопрос 5. Host header

**Вопрос:** как обрабатывать неизвестный Host?

**Решение:** default server возвращает `444` (No Response) или `400 Bad Request` для неизвестного Host и прямых запросов по IP без корректного Host. Основной server блок обслуживает только `localhost`, `127.0.0.1` и `${SERVER_NAME:-localhost}`.

### Вопрос 6. HTTP security headers

**Вопрос:** нужны ли защитные HTTP-заголовки?

**Решение:** используется собственный локальный CSS/JS без внешних CDN, чтобы включить строгий CSP:

```text
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'
```

Также обязательны `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` и `Referrer-Policy: no-referrer`.

### Вопрос 7. IPv4-only

**Вопрос:** как отключить IPv6?

**Решение:** Compose использует только IPv4 CIDR и `enable_ipv6: false`, если это поддерживается bridge-драйвером. Проверки выполняются через IPv4 loopback `127.0.0.1`.

### Вопрос 8. Egress isolation

**Вопрос:** как проверять deny-by-default egress?

**Решение:** использовать оба уровня проверки:

1. статический Pytest policy-тест Compose-манифеста, проверяющий `internal: true` и отсутствие лишних сетей;
2. runtime-интеграционный тест через `docker compose exec`, проверяющий недоступность внешних ресурсов с жёстким timeout 2 секунды.

Тесты не должны зависеть от конкретного доступного интернет-ресурса; они проверяют контролируемые сетевые признаки и timeout.

### Вопрос 9. Cowrie -> Target App/Nginx

**Вопрос:** что проверять из Honeynet?

**Решение:** проверяются оба способа адресации:

- Docker DNS-имена `target-app` и `nginx` не должны разрешаться из Cowrie;
- TCP-пробы на IP-адреса `prod_net`, включая адреса Target App и Nginx, должны завершаться `Network Unreachable` или timeout не более 2 секунд.

### Вопрос 10. Target App -> Honeynet

**Вопрос:** должна ли изоляция быть симметричной?

**Решение:** да. Target App не разрешает `cowrie`, не имеет маршрутов в `honeynet` и не может подключиться к портам Cowrie `2222/2223`.

### Вопрос 11. Статические Compose policy tests

**Вопрос:** какие свойства проверять без запуска сервисов?

**Решение:** Pytest проверяет:

- наличие `prod_net`, `honeynet` и отдельной `cowrie_ingress`;
- состав сетей: HTTP Nginx и Target App только в `prod_net`, Cowrie только в
  `honeynet`, TCP ingress в `honeynet` и `cowrie_ingress`;
- отсутствие `ports` у Target App;
- публикацию TCP ingress только на `2222` и `2223` без прямых host ports у Cowrie;
- использование `${BIND_ADDRESS}` и default `127.0.0.1`;
- `honeynet.internal: true` и ожидаемые IPv4 CIDR;
- non-root, `cap_drop`, `no-new-privileges`, resource limits;
- отсутствие privileged, host network, Docker socket и иных лишних сетей;
- наличие healthchecks.

### Вопрос 12. Healthchecks

**Вопрос:** как проверять готовность сервисов?

**Решение:**

- Cowrie: TCP checks портов `2222` и `2223`;
- Target App: HTTP `GET /health` внутри `prod_net`;
- Nginx: HTTP `GET /health` снаружи через `8080`, проксируемый к Target App.

Сервисы используют `depends_on` с `condition: service_healthy`, где это поддерживается Compose.

### Вопрос 13. Поведение при отказе

**Вопрос:** что происходит при падении контейнера?

**Решение:** Nginx, Target App и Cowrie используют `restart: unless-stopped`. Named volumes сохраняют данные между перезапусками.

### Вопрос 14. Тестовые сценарии Target App

**Вопрос:** какие функциональные и security-тесты обязательны?

**Решение:** тестируются UI, лабораторный warning badge, `/docs`, `/redoc`, `/openapi.json`, `/health`, лимит body, лимиты полей, timeout и размер вывода Command Injection, SQLi-поиск, Prompt Injection logging и отсутствие внешней LLM.

Контролируемые positive security fixtures обязательны:

- SQLi payload `' OR '1'='1` возвращает все synthetic seed-записи;
- Command Injection payload `127.0.0.1; echo "vuln_verified"` возвращает `vuln_verified` в stdout и завершается в пределах 5 секунд.

Ошибки не должны содержать stack trace или пути файловой системы хоста.

### Вопрос 15. DAST smoke

**Вопрос:** входит ли автоматизация ZAP/Nikto в Фазу 1?

**Решение:** нет. Фаза 1 готовит endpoints, валидирует OpenAPI-схему и добавляет в runbook примеры ручного запуска ZAP/Nikto. Автоматизированный DAST runner относится к последующей фазе.

### Вопрос 16. Логирование и секреты

**Вопрос:** какие требования к данным и проверкам секретов?

**Решение:** реальные секреты отсутствуют; используются только synthetic credentials и данные. `.env` не коммитится, `.env.example` содержит безопасные значения, payloads и credentials не попадают в Git, volumes не входят в репозиторий, log rotation в Фазе 1 не требуется.

Статический security scan через существующие Gitleaks/Trivy должен проверять Compose-файлы и security fixtures на отсутствие реальных токенов и известных проблем.

### Вопрос 17. Runbook и организация файлов

**Вопрос:** где разместить Compose и какие операции документировать?

**Решение:** основной манифест размещается в `deploy/docker-compose.yml` либо `infrastructure/compose/docker-compose.yml`; допускается симлинк в корень для удобства, но канонический путь должен быть один.

Runbook документирует копирование `.env.example`, `config`, запуск, статус, логи, изоляционные тесты, проверку localhost-портов, UI, SSH/Telnet, Cowrie JSON logs и teardown через `down`/`down -v`. Отдельно предупреждается, что `BIND_ADDRESS=0.0.0.0` допустим только в изолированной лаборатории.

### Вопрос 18. Финальные acceptance criteria

**Вопрос:** какие критерии определяют готовность Фазы 1?

**Решение:** все критерии обязательны:

1. `docker compose config` завершается успешно.
2. Все сервисы стартуют с заданными healthchecks.
3. Nginx принимает HTTP на `BIND_ADDRESS:8080`.
4. Cowrie принимает SSH/Telnet на `BIND_ADDRESS:2222/2223`.
5. Target App не имеет прямого host port mapping.
6. Только Nginx доступен к Target App по HTTP.
7. Cowrie и Target App находятся в разных Docker-сетях.
8. Runtime-тесты подтверждают двунаправленную изоляцию.
9. Runtime-тесты подтверждают отсутствие egress, где это возможно без зависимости от внешней сети.
10. Cowrie пишет raw JSON logs в `cowrie-logs`.
11. Cowrie сохраняет downloads в `cowrie-downloads`.
12. Nginx пишет JSON access logs в `nginx-logs`.
13. Target App сохраняет SQLite в `target-app-data`.
14. Target App UI содержит laboratory warning.
15. `/docs`, `/redoc` и `/openapi.json` доступны.
16. Command Injection, SQLi и Prompt Injection surfaces доступны согласно протоколу.
17. Ограничения body size, field length, timeout и output size проверены тестами.
18. Контейнеры запускаются non-root и имеют security baseline.
19. В Compose нет privileged mode, host networking, Docker socket или лишних capabilities.
20. `.env.example`, runbook и тесты присутствуют.
21. `git diff --check`, quality gate и security policy проходят.
22. Все тестовые команды воспроизводимы на чистом checkout.

## Статус интервью

Интервью по Блокам 1–3 завершено. Следующий артефакт — детальная спецификация Фазы 1 на основе этого протокола, `CONTEXT.md` и спецификации Фазы 0.
