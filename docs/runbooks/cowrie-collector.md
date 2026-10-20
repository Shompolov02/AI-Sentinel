# Cowrie → Fluent Bit → Core (#46)

Сначала выполните [подготовку Core](core-intake.md): существующий лабораторный
пароль, сервисный токен, CA и сертификат. Проверьте Docker/VPN/host routes по
тому же runbook. Новых подсетей и опубликованных портов сборщик не добавляет.
В игнорируемом `.env` задайте стабильный `COWRIE_SENSOR_ID=cowrie-lab`.

## Запуск девяти сервисов

```sh
make bootstrap
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml config --quiet
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml up -d --build --wait
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml ps
```

Ожидаются девять healthy-сервисов. Collector работает как UID 10001 с
дополнительной группой 999 для чтения Cowrie. Исходный журнал и root filesystem
монтируются read-only. Writable — только collector-data и tmpfs. Collector
подключён только к core_ingest, Cowrie — только к honeynet. Нет подключения к
prod_net, core_management, Docker socket или нового host-порта.

Python input adapter читает Cowrie и связывает входы с session.connect.
В одной транзакции сохраняются очищенный outbox и позиция чтения. Только
нормализованные события без пароля поступают в stdin Fluent Bit и его дисковые
chunks. HTTP output направлен в адаптер на loopback того же контейнера.
Адаптер отправляет событие в Core через TLS с проверкой CA/имени и токеном из
файла. Только durable 202 от Core подтверждает outbox. Повтор после сбоя
сохраняет event_id, время первого приёма и task_id.

## Ручная проверка

Используйте синтетического пользователя и лабораторный пароль, вводимый
интерактивно. Не используйте настоящие учётные данные:

```sh
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2222 synthetic-ssh@127.0.0.1
telnet 127.0.0.1 2223
```

На странице Core после входа SecOps появляется задача. Отказ получает Low и
Rules с Evidence и ссылкой. Успех — «не удалось оценить», без Low, с пояснением
об ожидаемом правиле #47. Команды и другие валидные типы Cowrie пока игнорируются.
LLM не вызывается. IP/порт источника, протокол и порт назначения берутся из
session.connect; недостающие обязательные значения не угадываются. Порт
назначения — порт Cowrie, а не переназначенный host-порт.

Локальный карантин, реестр поколений файлов и принятые номера задач:

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml exec -T collector python -c "import json,os; from pathlib import Path; from ai_sentinel_core.telemetry import Journal; print(json.dumps(Journal(Path('/data/collector.db'),os.environ['COWRIE_SENSOR_ID']).status(),indent=2))"
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml logs --tail 100 collector
```

`record_quarantined` предупреждает о повреждении или отсутствующем происхождении.
Карантин содержит ссылку, причину, длину и digest; исходный текст остаётся только
в сыром журнале. Ссылка заканчивается поколением файла и байтовым смещением;
имя файла ищется в локальном реестре. Core пока не открывает сырой источник.
Переименование при ротации сохраняет ID, truncation или изменение первой строки
создаёт новое поколение. Копия на другом inode — новый источник. Сохраняйте
collector-data и имя сенсора. Незавершённая строка ждёт newline; слишком длинная
попадает в карантин. Не сбрасывайте позиции вручную.

`core_delivery_unavailable` означает сохранённую ожидающую доставку. Проверьте
Core, срок CA/сертификата и файл токена. `collector_stopped` — критический отказ
приёма: проверьте права, место тома и health контейнера. Не отключайте TLS.
Collector использует последний непустой токен общего файла: добавьте новый,
проверьте доставку и отзовите старый по Core runbook. При смене CA обновите
trust bundle до смены server certificate и пересоздайте collector для перечитывания
TLS context. CA private key никогда не монтируется. Retention и политика
ёмкости/истечения буфера относятся к #51/#52; проверяйте место на диске стенда.

## Автоматизированная приёмка

Остановите ручной стенд без удаления томов перед harness с теми же подсетями:

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml down
make test-core-runtime
make test-runtime
make quality
```

Core runtime проверяет прежний синтетический путь (8 сервисов) и реальный
Cowrie (9). Во втором сценарии SSH создаёт отказ, Telnet — успех; при остановленном intake
проверяются дисковые chunks и отсутствие синтетического пароля во всех файлах
collector-data. Повреждённая тестовая строка изолируется. Пересоздание collector
сохраняет pending-события; после восстановления intake отказ получает Low,
а успех — failed без вердикта с причиной #47 на странице. Replay не меняет задачу, Evidence, вердикт и аудит. Запись в сырой
mount отклоняется. Cowrie/Target App проверяются на недоступность управляющих
сервисов по DNS и прямым IP, включая collector. Harness удаляет только собственный
случайно названный test project и его тома.

## Остановка и откат

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml -f deploy/collector.compose.yml down
```

Не добавляйте `-v`: потеря collector-data теряет поколения и стабильные ID,
потеря core-data — историю задач. Резервное копирование пока не реализовано.
Откат: предыдущий checkout и только Phase 1 + Core manifests; сохранить все тома.
Новая SQLite-схема относится только к отдельной БД collector.
