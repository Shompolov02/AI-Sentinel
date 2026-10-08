# Фаза 1: runtime-решения локального Honeynet-стенда

Каноническое принятое решение для Issue #19 —
`docs/architecture/decisions/phase-1-runtime-baseline.md`. Этот документ
согласует спецификацию с текущим Compose и HTTP edge из Issue #24.

## Compose и quality interface

Единственный Compose-манифест стенда — `deploy/docker-compose.yml`. Все команды
используют `docker compose -f deploy/docker-compose.yml`. Фазовый smoke baseline
`infrastructure/compose/smoke.yaml` остаётся отдельной проверкой. `make quality`
сохраняет проверки Фазы 0 и валидирует конфигурацию Compose; `make test-runtime`
проводит обязательную runtime-приёмку в доступном Docker Engine.

Cowrie закреплён как
`cowrie/cowrie:3.0.15@sha256:fc57120d88c2bfb5817f63f6c132ce5c2969b641c2f1ac67887652b6f294148d`.

## HTTP ingress, ошибки и корреляция

Nginx — единственный опубликованный HTTP-вход. Он проксирует `/health` и
остальные маршруты на `target-app:8000`; неизвестный Host закрывает с `444`.
Target App сохраняет принятый JSON-контракт ошибок: `error`,
`correlation_id`, `status`.

Nginx выпускает новый `$request_id` на каждом запросе, заменяет клиентский
`X-Request-ID` и передаёт значение приложению. В Compose-режиме Target App
возвращает его в `X-Request-ID`, допустимых телах ответа и JSON-журнале;
Nginx записывает тот же ID в JSON access log. При прямом запуске приложение
генерирует свой ID. Nginx формирует `X-Real-IP`, `X-Forwarded-For`,
`X-Forwarded-Host` и `X-Forwarded-Proto` из фактического ingress-соединения,
а прочие распространённые forwarding headers удаляет. Клиентская цепочка
forwarded адресов не используется.

## Runtime harness

Pytest suite в `tests/integration/` использует Docker Compose plugin и
канонический манифест. Для каждого запуска выбираются отдельный project name
и host HTTP port; очистка всегда выполняет `down --volumes --remove-orphans`.
Локальный запуск без Docker явно пропускается, а `make test-runtime` и CI
требуют Docker Engine и завершаются ошибкой при его недоступности. Тесты
проверяют опубликованный HTTP, логи и отсутствие доступа Nginx к Cowrie.
