# AI-Sentinel

AI-Sentinel (САЗИИ) — greenfield-монорепозиторий для системы активной сетевой защиты и автоматического реагирования на инциденты на базе ИИ-агента.

На текущем этапе репозиторий содержит только базовый каркас областей ответственности. AI Agent Core, Prompt Guard, LLM Client, Triage Engine, Honeynet, SOAR, сетевые политики и прикладные контракты ещё не реализованы.

## Карта репозитория

| Область | Назначение |
| --- | --- |
| `services/` | Будущие самостоятельно разворачиваемые сервисы САЗИИ |
| `packages/` | Переиспользуемые версионируемые Python-пакеты |
| `infrastructure/` | Будущие декларативные шаблоны контейнеров и окружений |
| `research/` | Исследовательские сценарии, датасеты и инструменты проверки |
| `tests/` | Общий каркас unit-, integration- и security-проверок |
| `docs/` | Архитектура, ADR, runbooks и нормативная документация |
| `scripts/` | Безопасные developer-инструменты репозитория |

`CONTEXT.md` — нормативный предметный язык и набор архитектурных ограничений. Открытые решения из него нельзя молча превращать в прикладные контракты.

## Локальное окружение

```text
cp .env.example .env
uv sync --all-packages --locked
uv run pytest
uv run ai-sentinel-smoke
```

Шаблон не содержит секретов, адресов инфраструктуры или выбранных провайдеров. Файл `.env` остаётся локальным и игнорируется Git.

Python workspace требует Python 3.10 или новее и управляется `uv`. Команда `uv sync --all-packages --locked` использует только зафиксированные зависимости и завершается ошибкой при расхождении `pyproject.toml` и `uv.lock`.

## Команды разработки

Канонический интерфейс разработки находится в `Makefile` и не требует ручной активации виртуального окружения:

```text
make bootstrap       # воспроизводимая установка из uv.lock
make format          # форматирование Ruff
make lint            # lint Ruff
make typecheck       # строгий mypy
make test            # pytest и coverage
make sast            # Semgrep, fail-closed
make sca             # pip-audit, fail-closed
make secrets         # Gitleaks, fail-closed
make security-exceptions # проверка срока и полноты Security Exceptions
make container-check # Trivy, fail-closed
make quality         # read-only полный quality gate
```

`quality` использует `ruff format --check`, поэтому не изменяет файлы. Security-команды намеренно завершаются с ошибкой, если соответствующий scanner не установлен.

Правила репозитория, роли, Definition of Done и процесс pull request описаны в
[`docs/governance.md`](docs/governance.md). Сообщения об угрозах направляются
через Security Exception/threat-reporting процесс в `docs/security/`; изменения
архитектуры оформляются ADR в `docs/adr/`.

## Правила изменений

Изменения оформляются Conventional Commits. Новая бизнес-логика разрабатывается по Red-Green-Refactor; security-контроли, CI и документация должны оставаться аудируемыми. Перед реализацией соответствующей области необходимо свериться с `CONTEXT.md` и архитектурными решениями.
