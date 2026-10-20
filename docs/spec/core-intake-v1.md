# Core intake v1 — issue #45

Контракт утверждён 2026-10-20; основание — #44 и ADR 0002.
Принимается только нормализованный отказ входа. Сырые записи и пароли не копируются.

`POST https://core-intake:8443/internal/events`, `Content-Type: application/json`,
`Authorization: Bearer <collector token>`, с проверкой CA и имени сервера.

```json
{
  "schema_version": 1,
  "event_id": "5697880a-7ac4-43db-bfe9-1692ee3cefc7",
  "occurred_at": "2026-10-20T10:00:00Z",
  "received_at": "2026-10-20T10:00:01Z",
  "event_type": "login_attempt",
  "cowrie_event_type": "cowrie.login.failed",
  "sensor_id": "cowrie-lab",
  "session_id": "synthetic-session-1",
  "source_ip": "192.0.2.10",
  "source_port": 41000,
  "protocol": "ssh",
  "destination_port": 2222,
  "raw_record_ref": "synthetic:login-1",
  "login": {
    "username": "synthetic",
    "outcome": "failure",
    "password_length": 12
  }
}
```

Все поля обязательны, неизвестные поля запрещены. Время включает часовой пояс;
ID события — UUID; source_ip — IPv4/IPv6; порты — целые 1–65535; длина пароля —
целое 0–65535. Строковые идентификаторы, логин и непрозрачная ссылка — 1–256
символов, протокол — ssh/telnet. HTTP proxy ограничивает тело 64 KiB.

Ответ 202 появляется после фиксации события и queued-задачи, до ожидания анализа:

```json
{
  "task_id": "990c9a94-d034-49c1-99fa-14a531e4939c",
  "correlation_id": "990c9a94-d034-49c1-99fa-14a531e4939c",
  "state": "queued"
}
```

Повтор того же нормализованного содержимого и event_id даёт прежнюю задачу
с её текущим состоянием. Изменение содержимого с тем же ID — 409.
401 означает отсутствие разрешения; 422 — неверный JSON-контракт; 503 — заполненную
очередь или недоступную SQLite. В этих случаях новая задача не подтверждается.
Идентификатор и его построение настоящим нормализатором — задача #46.

Состояния: queued → processing → completed или failed. При failed вердикта нет.
`GET /api/tasks/{task_id}` требует пользовательский сеанс SecOps и возвращает
`task_id`, `correlation_id`, `state`, `created_at` (Unix UTC), `event`, `history`,
`verdict`, `evidence`, `audit`. Несуществующая задача — 404.

Вердикт содержит severity=Low, reason, analysis_method=Rules,
rules_version=login-failure-v1, guard_result=not_applicable, mitre_attack=null
(«не определена») и evidence_ids. Low относится к факту отказа входа;
счётчики серий и успехи не реализованы до #47. Evidence содержит UUID id,
event_id, raw_record_ref, source_kind (synthetic/reference_only) и facts с
outcome=failure, protocol и cowrie_event_type. Core не открывает эту ссылку как
файл или URL. Сырые записи на странице не выдаются в #45.

Аудит задачи содержит id, at (Unix UTC), action, actor, task_id, correlation_id и
details. Действия: event_accepted, processing, verdict_created, completed/failed.
Отдельные записи login_succeeded фиксируют роль SecOps и время успешного входа,
видны в списке задач. Записи не перезаписываются. Полный текст HTTP-запросов,
пароли и токены в аудит не включаются.

`GET /login` — форма; `POST /login` принимает JSON `{ "password": "…" }` и выдаёт
HttpOnly/SameSite=Strict cookie. GET /tasks и /tasks/{task_id} — страницы только
чтения. Успешный явный просмотр продлевает idle timeout 1800 секунд; poll=1 не
продлевает его. Действует один SecOps, без журнала неудачных входов и без задержки
после неверных паролей. Подробности запуска и ротации — в Core runbook.
