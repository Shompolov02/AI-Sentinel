# Приёмка Cowrie / Fluent Bit — issue #46

Дата: 2026-10-21 (Europe/Moscow). macOS arm64, Docker Engine 29.2.0,
Compose 5.0.2, uv 0.12.17, основной Python 3.14.6. База main:
`d061a6859d6a55464de362d22d49702d7d95bc94` (PR #56, закрытая #45).
Ветка реализации: `codex/issue-46-cowrie-collector`.
Решения ID, отсутствия пароля в буфере, успешного входа без оценки и границы
TDD-тестов подтверждены владельцем; зафиксированы в ADR 0003.

## Acceptance criteria

- [x] Источник Cowrie монтируется сборщику read-only. Input adapter нормализует
  до stdin Fluent Bit и до его filesystem chunks. Сохраняются время, тип,
  сенсор, сессия, источник, протокол, исход и ссылка; пароль заменяется длиной.
- [x] UUIDv5 связывает сенсор, постоянное поколение файла и байтовое смещение.
  Outbox сохраняет received_at; Core возвращает прежний task_id без нового
  анализа. Повреждённая запись исключается из доставки, локальный карантин
  хранит ссылку/причину/digest/длину и подаёт сигнал, не копируя сырой текст.
- [x] Реальные SSH/Telnet-действия проходят до задач и страницы Core.
  Отказ получает Low, успех — failed без вердикта до #47. Cowrie остаётся
  только в honeynet; DNS и прямые IP управляющих сервисов недоступны.

## Проверки

| Проверка | Результат |
| --- | --- |
| `make quality` | PASS: 88 обычных тестов, Ruff format/lint, strict mypy, Semgrep, SCA, Gitleaks, Security Exceptions, Trivy, SBOM |
| Python 3.10.6 / 3.11.4, Core API и сборщик | PASS: 23 относящихся к задаче теста; после последних изменений отдельно 10 тестов нормализатора/Compose policy |
| `AI_SENTINEL_RUNTIME_REUSE_IMAGES=1 make test-runtime` | PASS: 16 passed, без skips, включая оба сценария Core и прежнюю Phase 1 |
| `git diff --check` | PASS |

Red → green выполнялся по одному поведению: отсутствие модуля → нормализация;
отсутствие acknowledgement → сохранение ID при повторе; отсутствующий status →
наблюдаемый карантин; успех без события → failed-задача без Low; неверная форма
сессии → карантин вместо остановки; незавершённая oversized-строка → ожидание
newline и корректные длина/digest. Тесты используют публичные границы, реальную
SQLite и API Core; сетевой отказ моделируется на внешней границе доставки.

Runtime harness использует только синтетические учётные данные, собственные
случайно названные projects и тома. Штатная UserDB Cowrie разрешает синтетический
Telnet-вход; для SSH используется гарантированно отклоняемый лабораторный пароль
root. Источник сравнивается с исходным session.connect: Docker Desktop может
передавать адрес host gateway вместо 127.0.0.1. Ожидаемый IP не подставляется.

Новых Security Exceptions нет. Trivy проверяет конфигурацию и образ collector;
в CI добавлена публикация этих отчётов.

Локальные отчёты в игнорируемой `.artifacts/`: `issue-46-quality-final.log`,
`issue-46-runtime-final.log`, `issue-46-py310-final.log`, `issue-46-py311-final.log`,
`semgrep.sarif`, `pip-audit.json`, `trivy-collector-config.json`,
`trivy-collector-image.json` и `sbom.cdx.json`. Воспроизведение описано в
`docs/runbooks/cowrie-collector.md` и `docs/runbooks/core-intake.md`.

## Границы и откат

В #46 нет команд, LLM, policy High для успешного входа, счётчиков серий,
просмотра сырого журнала и retention/overflow/expiry jobs. Успешный вход создаёт
failed-задачу с причиной `login_success_policy_pending_47`; вердикт не выдумывается.
Резервного копирования нет; потеря collector-data теряет source identities,
потеря core-data — историю. Rename rotation сохраняет поколения; копия файла на
другом inode считается новым источником.

Откат: остановить три Compose manifests без `-v`, сохранить все тома и перейти
на прежний checkout с Phase 1 + Core. Три исходных неотслеживаемых документа
не включаются в PR и остаются в рабочем дереве владельца.
