# Фаза 1: runtime-решения локального Honeynet-стенда

Этот документ фиксирует решения реализации из Issue #19. Он дополняет спецификацию Фазы 1, не реализуя сам стенд и не меняя границы фазы.

## Канонический Compose и quality interface

Единственный Compose-манифест локального Honeynet runtime — `infrastructure/compose/honeynet.yaml`. Команды запуска, проверки и будущий runtime harness должны передавать только этот путь через `docker compose -f infrastructure/compose/honeynet.yaml`; альтернативные копии Compose-манифеста для стенда не создаются. `infrastructure/compose/smoke.yaml` остаётся независимым smoke-baseline Фазы 0 и не является стендом Honeynet.

Общий acceptance seam остаётся `make quality`, согласно интерфейсу Фазы 0. Цель `quality` запускает текущие проверки без исключений и ослаблений; `container-check` валидирует нормализуемую Compose-конфигурацию стенда командой `docker compose -f infrastructure/compose/honeynet.yaml config --quiet` наряду с существующей проверкой smoke baseline и Trivy gates. Отдельные `make` цели остаются диагностическими подкомандами, не заменяющими общий gate.

Образ Cowrie закрепляется ровно как `cowrie/cowrie:3.0.15@sha256:fc57120d88c2bfb5817f63f6c132ce5c2969b641c2f1ac67887652b6f294148d`. Ни `latest`, ни тег `v3.0.15` не используются.

## HTTP ingress и health

Nginx маршрутизирует `GET /health` так же, как остальные запросы приложения: запрос проксируется в Target App, а ответ отражает его доступность; отдельный локальный ответ Nginx не маскирует недоступность upstream. Endpoint не раскрывает внутренние сведения об инфраструктуре.

Запрос с неизвестным `Host` отклоняется Nginx со статусом `444` (соединение закрывается без HTTP body). Запросы с разрешённым Host проходят к приложению. Runtime-проверки удостоверяются, что неизвестный Host не достигает Target App.

## HTTP error и correlation contract

Все ошибки HTTP endpoints Target App, включая ошибки валидации, используют единый JSON формат RFC 9457 `application/problem+json`:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "Request could not be processed",
  "instance": "/api/example",
  "request_id": "<server-generated-id>"
}
```

`type`, `title`, `status`, `detail` и `instance` следуют Problem Details; `request_id` — обязательное строковое расширение. Сообщение `detail` безопасно для клиента: оно не содержит traceback, SQL, абсолютных путей или секретов. Для каждого HTTP-ответа, включая ошибки и `/health`, приложение задаёт `X-Request-ID`; значение совпадает с `request_id` тела там, где тело существует. При успешном ответе без JSON body идентификатор остаётся в заголовке.

Приложение всегда генерирует новый непрозрачный `X-Request-ID` на границе доверия и перезаписывает любое клиентское значение, включая корректно выглядящее. Для исходящего запроса Nginx к Target App Nginx устанавливает собственный request ID в `X-Request-ID`; приложение создаёт свой authoritative ID и возвращает его наружу. Идентификатор не используется как аутентификация или авторизация.

Клиентским `X-Forwarded-*` заголовкам доверять нельзя. Nginx удаляет/перезаписывает входящие `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` и связанные forwarding headers, формируя значения только из известного ingress-соединения и настроенного Host. Target App доступен только в `prod_net` через Nginx и не определяет схему, клиента или внешний Host по произвольным заголовкам. Доверенные proxy hops задаются явно, не через широкое доверие любому proxy.

## Единый runtime test harness

Runtime проверки стенда реализуются как pytest integration suite в `tests/integration/`, использующая установленный локальный Docker Compose plugin (`docker compose`) и единый манифест. Harness проверяет доступность Docker Engine/Compose заранее и при недоступности завершает тест явным `pytest.skip` с причиной; в CI/runtime acceptance окружении такая недоступность не считается успешной приёмкой. Для работы и очистки всегда используется тот же `-f infrastructure/compose/honeynet.yaml` и project name, изолированный для запуска.

Общий lifecycle harness: `docker compose -p <isolated-project> -f infrastructure/compose/honeynet.yaml config --quiet`, затем `up -d --wait`, проверки HTTP и TCP с host, при необходимости `exec` для сетевых/изоляционных проверок внутри сервисов, затем `down --volumes --remove-orphans` в гарантированной очистке. Тесты не требуют внешнего интернета; локальные Docker Engine/Compose среды поддерживаются, если они выполняют стандартную Compose v2 модель `config`, `up --wait`, `exec` и `down`. Ошибка проверки не должна пропускаться или превращаться в warning.

Harness проверяет проксируемый `/health`, отказ неизвестного Host, error JSON и совпадение correlation ID в заголовке/теле, замену поддельного `X-Request-ID` и нейтрализацию поддельных forwarding headers. Сетевые runtime assertions дополняют, а не заменяют статические Compose policy checks.

## Границы

Эти решения относятся только к локальному Compose runtime Фазы 1: Nginx, Target App и Cowrie. Они не добавляют K3s, Ansible, Fluent Bit, LLM/LLM Client, SOAR, DAST runner, CI deployment или production ingress. Подробный runbook и исполняемый Honeynet stack реализуются последующими задачами Фазы 1.