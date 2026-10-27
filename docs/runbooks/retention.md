# Runbook: сроки хранения Cowrie/Core (#51)

Текст живёт 14 суток от первого приёма телеметрией, метаданные задачи — 30 суток.
Доставка, анализ, повтор и сжатие не продлевают срок. TTY, служебный журнал и
stdin/redirection-копии наследуют срок начала сессии: новые фрагменты долгой
сессии могут удалиться раньше. Неизвестный исторический срок текста означает
удаление при миграции, без нового TTL. Лабораторный стенд не имеет резервной копии.
Политика — [retention v1](../spec/core-retention-v1.md), решение — [ADR 0008](../adr/0008-cowrie-retention.md).

## Конфигурация

Используйте терминал с прежними переменными проекта и тем же Compose project.
Подготовка credentials/TLS — [Core](core-intake.md), [reader](evidence-source.md),
закреплённые локальные веса — [Guard](cowrie-command-guard.md). Новые секреты
для очистителя не нужны. Системные часы хоста менять нельзя.

```sh
export CORE_GUARD_MODEL_DIR="$PWD/.local/prompt-guard/model"
sentinel_retention() {
  docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml \
    -f deploy/collector.compose.yml -f deploy/evidence.compose.yml \
    -f deploy/guard.compose.yml -f deploy/retention.compose.yml "$@"
}
sentinel_retention config --quiet
```

Без ML при диагностике можно убрать Guard overlay, сохранив остальные:
команды будут завершаться `guard_unavailable`, а не Low. Полная приёмка требует
реальных закреплённых весов. Без retention overlay Core удаляет свой текст,
но удаление сырья/TTY/служебных копий всего стенда не обеспечено.

Очиститель работает как Cowrie UID/GID `999`, без сети, портов, root и capabilities.
Ему доступны только logs, downloads, подкаталог `tty` и реестр collector.
SSH-ключи Cowrie, Core SQLite, пароль, токены, TLS-ключи и модель не монтируются.
Collector остаётся UID `10001`; его `/data` и реестр доступны группе `999`
(`2770`/`0660`), а приватные chunks остаются у collector. Cowrie не имеет
mount реестра. Reader сохраняет read-only mounts и не получает право очистки.
Core `/data` остаётся приватным, UID/GID `10001`.

## Первое обновление существующего стенда

Это отдельная операция обновления. Однократное пересоздание Cowrie для смены
logger завершает текущие сессии; фоновая очистка после обновления Cowrie не
останавливает. Используйте только текущий проект, не создавайте новый project
с другими томами вместо обновления старого.

1. Проверьте logging driver текущего Cowrie, не выводя содержимое журнала:

   ```sh
   retention_cowrie_id="$(sentinel_retention ps -q cowrie)"
   docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$retention_cowrie_id"
   ```

   Для стандартного локального driver старый контейнер удаляется Compose при
   пересоздании вместе с его локальным Docker-журналом. Если журнал отправляется
   внешнему driver/агенту, его копии должны удаляться отдельно по той же политике;
   Docker socket в очиститель добавлять нельзя.

2. Остановите потребителей на время миграции, сохранив volumes:

   ```sh
   sentinel_retention stop retention collector core-intake core-page core raw-reader
   sentinel_retention up -d --no-deps --force-recreate --wait cowrie
   sentinel_retention up -d --build --wait
   sentinel_retention ps --all
   ```

   Cowrie использует штатный файловый logger и umask `0002`, не дублирует команды
   в Docker stdout. Старый контейнер со stdout-копиями не оставляется архивом.
   Новый collector как владелец реестра настраивает общую группу до readiness,
   проверяет secure SQLite и выполняет миграцию. Старые и новые writer одновременно
   не запускаются; hot journal/WAL восстанавливает SQLite, вручную их не удаляют.
   Не создавайте дамп или полную копию базы/сырья как часть этой миграции.

3. Проверьте готовность, режимы и отсутствие лишних полномочий:

   ```sh
   sentinel_retention exec -T collector stat -c '%a %u:%g %n' /data /data/collector.db /data/collector.db.retention.lock
   sentinel_retention exec -T core stat -c '%a %u:%g %n' /data
   sentinel_retention logs --tail 50 retention collector core
   ```

   Ожидание: collector directory `2770`, реестр/lock `660`, группа `999`;
   Core `/data` — `700`, `10001:10001`. Все сервисы healthy; нет повторяющегося
   `retention_cleanup_failed`. Диагностика содержит коды/ссылки, без команд.
   Ошибка владельца/группы или недоступный mount не исправляются запуском root,
   выдачей `777`, отключением secure_delete или удалением реестра.

## Штатное обслуживание

```sh
sentinel_retention exec -T core python -m ai_sentinel_core.retention --role core --once
sentinel_retention exec -T retention python -m ai_sentinel_core.retention --role raw --once
sentinel_retention exec -T collector python -m ai_sentinel_core.retention --role collector --once
```

Exit 0 означает завершение наступивших операций данной роли. Exit 1 и критический
`retention_cleanup_failed` означают ошибку или незавершённое удаление; повторяют
после восстановления доступа/места. Успешный `/health` сам по себе не доказывает
отсутствия текста в томах. На работающем collector сбрасывается только дочерний
Fluent Bit: chunks затираются, допустимый outbox передаётся повторно. Cowrie и
его сессии продолжаются. Истёкшее недоставленное событие даёт локальный критический
`buffer_event_expired`; ёмкость/перегрузка относятся к #52.

Core закрывает выдачу/новый анализ просроченного текста независимо от фонового
цикла. Пока физическое удаление источника не подтверждено, raw даёт 503 без
фрагмента. После подтверждения — 410 и «Источник удалён», без excerpt/raw URL.
Вердикт и объяснение без цитат остаются до 30 суток, затем задача даёт 404 и
не находится поиском. Команда без достаточных данных получает failed/text_expired
с предупреждением; вход может закончить Rules по безопасным оставшимся полям.

Gzip-архиватор публикует только завершённый файл атомарным переименованием,
не изменяет закрытый архив во время обслуживания. Срок не берётся из mtime.
Повреждённый gzip, неподтверждённый fingerprint или незавершённая замена не
считаются успешной очисткой. Не удаляйте `.retention-*` и журнал операции вручную:
повторный запуск завершает замену либо затирает незавершённый временный результат.

## Проверка на собственных тестовых томах

```sh
uv run pytest -q tests/unit/test_retention.py tests/unit/test_retention_lifecycle.py
CORE_GUARD_MODEL_DIR="$PWD/.local/prompt-guard/model" AI_SENTINEL_REQUIRE_GUARD=1 \
  uv run pytest -q -m runtime tests/integration/test_retention_stack_runtime.py
```

Тестовый clock смонтирован только в собственный harness и не является настройкой
production HTTP. Проверяются настоящий Cowrie, Fluent Bit, TLS, Guard, reader,
живые сессии, удаление в файлах и 30-дневная история. Тест создаёт случайный project,
временные credentials и собственные тома; удаляет только их. Обычная остановка
стенда — `sentinel_retention down`, без `-v`. Откат на старый код/отключение
очистителя не сохраняют политику 14/30; это не штатный rollback с сохранением SLA.
