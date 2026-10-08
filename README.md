# AI-Sentinel

AI-Sentinel (САЗИИ) — greenfield-монорепозиторий для системы активной сетевой защиты и автоматического реагирования на инциденты на базе ИИ-агента.

На Фазе 1 реализован лабораторный Target App с синтетическим каталогом активов и контролируемыми поверхностями SQL Injection, Command Injection и Prompt Injection. AI Agent Core, Prompt Guard, LLM Client, Triage Engine и SOAR ещё не реализованы.

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

## Лабораторный Target App

Для локального запуска из корня репозитория:

```text
uv run uvicorn target_app.main:app --app-dir services/target-app --reload --port 8000
```

Русский интерфейс доступен на `http://localhost:8000/`, локальная документация API — на `/docs`, проверка состояния — на `/health`. Поиск обращается только к синтетической SQLite-базе в `services/target-app/target_app/data/`; каталог создаётся автоматически и игнорируется Git.

Воспроизводимые лабораторные примеры: запрос `' OR '1'='1` в поиске возвращает все исходные активы; цель `127.0.0.1; echo "vuln_verified"` в диагностике показывает результат командной инъекции. Поле анализа событий только записывает недоверенный текст и correlation ID в структурированный журнал; LLM не вызывается. Эти поверхности предназначены исключительно для изолированного стенда.

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
