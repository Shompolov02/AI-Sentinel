# Runbook: первый срез Core (#45)

Сценарий: синтетический нормализованный отказ входа → TLS-приём → номер задачи →
обоснованный Low и Evidence на HTTP-странице SecOps. Реальный сборщик Cowrie описан в [runbook #46](cowrie-collector.md);
серии входов, команды, LLM и очистка по сроку реализуются в следующих issues #44.
Core принимает только отказ входа; другие типы отклоняются, а не получают Low.
Данные задач и аудита сохраняются в SQLite на `core-data`; резервной копии нет.

## Подготовка

Из корня репозитория выполните:

```sh
make bootstrap
uv run python scripts/core_credentials.py secrets/core
sh scripts/core_tls.sh secrets/core
```

Утилита дважды запросит **существующий лабораторный пароль** скрытым вводом.
На диск попадает только salted scrypt verifier; пароль не передаётся через CLI
или переменную среды. Сервисный токен создаётся случайно (256 бит).
Ни одна команда не перезаписывает существующие учётные данные или ключи TLS.
Владелец стенда — единственный SecOps; общий пароль второму человеку не выдаётся.

Каталог `secrets/core` имеет режим 0700 и игнорируется Git и Docker build context.
Отдельные файлы для bind mounts читаются непривилегированными UID контейнеров;
на хосте доступ к ним ограничен закрытым родительским каталогом. CA private key
имеет режим 0600 и **не монтируется** в контейнеры. Не переносите эти файлы в
общедоступный каталог и не выводите токены в журнал или историю команд.

В локальный `.env` добавьте:

```dotenv
CORE_SECRETS_DIR=../secrets/core
CORE_BIND_ADDRESS=127.0.0.1
CORE_HTTP_PORT=8082
CORE_INGEST_SUBNET=172.30.60.0/24
CORE_MANAGEMENT_SUBNET=172.30.70.0/24
CORE_HTTP_INGRESS_SUBNET=172.30.80.0/24
```

`CORE_SECRETS_DIR` в Compose разрешается относительно каталога `deploy/`.
Абсолютный путь также допустим. `CORE_BIND_ADDRESS` обязателен: для доступа
с другого устройства укажите адрес лабораторного интерфейса сервера. Адрес
публикации Cowrie от этого не меняется. Прямой HTTP передаёт пароль и содержимое
страницы открыто; это принятое ограничение первой лабораторной версии.

Проверьте существующие Docker/VPN/host routes и отсутствие пересечений восьми
подсетей перед запуском. На macOS:

```sh
docker network ls
netstat -rn -f inet
# Для каждого существующего Docker network:
docker network inspect NETWORK_NAME
```

Новые подсети не пересекаются с пятью стандартными подсетями Phase 1.
Если адреса заняты, задайте свободные через `.env` и повторите проверку.

## Конфигурация и запуск

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml config --quiet
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml config
# Сначала проверьте host_ip и отсутствие host-порта у core/core-intake.
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml up -d --build --wait
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml ps
```

Объединённый стенд имеет восемь healthy-сервисов. `core` подключён только к
`core_management`; TLS proxy `core-intake` — к `core_ingest` и `core_management`;
HTTP proxy `core-page` — к `core_management` и `core_http_ingress`. Cowrie остаётся
только в `honeynet`. Сборщик получает доступ только к `core_ingest`, CA-сертификат
и свой сервисный токен. В #45 вместо будущего Fluent Bit используется тестовый
синтетический клиент. Приём — `https://core-intake:8443/internal/events`;
отключать проверку CA или имени сертификата нельзя. Nginx завершает TLS на
границе приёма; HTTP upstream `core:8000` доступен только в закрытой управляющей
сети. Страница не проксирует `/internal/*`.

Откройте `http://127.0.0.1:8082/login` (или заданный адрес), войдите существующим
паролем. Страница позволяет только читать задачи, результаты и аудит успешных
входов. Неверные входы не журналируются. Просмотр страницы и карточки обновляет
30-минутный срок сеанса; автоматическое обновление с `poll=1` его не продлевает.
Evidence и страницы имеют `Cache-Control: no-store`; HTML из события экранируется.

JSON-пример нормализованного события и ожидаемые ответы находятся в
`docs/spec/core-intake-v1.md`. Пароль и сырая Cowrie-запись не принимаются.
Повторный event_id с тем же содержимым возвращает прежнюю задачу; другое
содержимое под тем же ID даёт 409. При 422 исправляют входные данные; при 503
сохраняют событие у отправителя и повторяют позже. Принятая задача переживает
пересоздание контейнера; незавершённая работа восстанавливается из SQLite.

## Проверка

Перед runtime harness остановите ручной стенд **без `-v`**: тест использует те же
подсети, но отдельный project и собственные временные тома.

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml down
make test
make test-core-runtime
make test-runtime
make quality
```

`test-core-runtime` генерирует отдельные временные CA/ключи и синтетические
учётные данные, поднимает Core и Cowrie, проверяет доверенный TLS, отказ без
токена и без доверенного CA, HTTP-вход, Low/Evidence/аудит, запрет записи через
страницу и сохранность после пересоздания Core. Проверяется недостижимость Core
из Cowrie. Удаляются только тома случайно названного тестового project.
`make test-runtime` дополнительно запускает прежние проверки всей Phase 1.
Отсутствующий Docker или ошибка приёмки не превращаются в успешный skip.
`make quality` сканирует также Dockerfile и образ Core. Semgrep и pip-audit
запускаются в отдельном Python 3.11 (SECURITY_PYTHON), независимо от версии
интерпретатора приложения. Это устраняет несовместимость сканера с Python 3.14.

Для повторной проверки уже собранных локальных образов при недоступном registry:

```sh
AI_SENTINEL_RUNTIME_REUSE_IMAGES=1 make test-core-runtime
```

Этот режим допустим только после сборки образов из проверяемого checkout.

## Сигналы и диагностика

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml ps --all
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml logs --tail 100 core core-intake core-page
```

`storage_unavailable` / `storage_failure` — критический сигнал: проверить
свободное место, доступность `core-data`, права и состояние файловой системы.
`analysis_error` сообщает о невозможности оценки; при доступной базе задача
переходит в «не удалось оценить». Переполнение 1000 незавершённых задач даёт 503:
сборщик должен сохранить запись и замедлиться. После устранения причины перезапуск
Core восстанавливает незавершённые задачи; не удаляйте том для исправления ошибки.
Nginx и Uvicorn не пишут access logs с реквизитами входа; сигналы не содержат
пароля, токена или полного события. При сбое БД нет подтверждения 202.

## Смена сервисного токена

Храните список из одного или двух непустых токенов в `collector-tokens`.
Для плановой смены создайте новый токен, временно сохранив старый:

```sh
uv run python - <<'PY'
from pathlib import Path
import secrets
p = Path('secrets/core/collector-tokens')
old = p.read_text().splitlines()
assert len(old) == 1
p.write_text(old[0] + '\n' + secrets.token_urlsafe(32) + '\n')
PY
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml up -d --force-recreate --wait core
```

Передайте новый (второй) токен сборщику через его закрытый файл конфигурации;
проверьте успешный TLS-приём. Затем оставьте только вторую строку и снова
пересоздайте Core. Проверьте: старый токен даёт 401, новый — 202.
Не смешивайте токен сборщика с пользовательским паролем. Изменение содержимого
читается при каждом запросе; пересоздание также гарантирует обновление bind mount
после замены файла через редактор/rename. При компрометации сначала отзовите
старый токен, затем восстановите сборщик; временный отказ 401 ожидаем.

## Обновление сертификата

CA действует 365 дней, серверный сертификат — 90 дней. Проверяйте даты до истечения:

```sh
openssl x509 -in secrets/core/intake.crt -noout -dates
openssl x509 -in secrets/core/intake.crt -checkend 2592000 -noout
```

Для ручной смены создайте свежий закрытый staging-каталог и выполните
`sh scripts/core_tls.sh secrets/core-tls-next`. Добавьте новый CA в trust bundle
сборщика **до** замены серверного сертификата, сохранив старый CA на время перехода.
Скопируйте новый server key/cert в действующие файлы `intake.key`/`intake.crt`,
пересоздайте `core-intake` через `up -d --force-recreate --wait core-intake` с обоими
Compose-файлами. Проверьте приём с проверкой имени `core-intake` и нового CA.
Удалите старый CA из доверия сборщика только после успешной проверки. CA private
key остаётся на хосте в закрытом каталоге; ключи не добавляются в образ/Git.
Ошибки выпуска не требуют отключать проверку TLS.

## Остановка и откат

```sh
docker compose -f deploy/docker-compose.yml -f deploy/core.compose.yml down
```

Без `-v` сохраняется `core-data` и прежние тома Phase 1. Откат: остановить Core,
вернуться к прежнему checkout и использовать обычный Phase 1 Compose без overlay.
Не запускайте одновременно два project с одинаковыми подсетями. Команда `down -v`
для рабочего стенда удалит задачи, Evidence и аудит; runbook её не требует.

`make test-core-runtime` также запускает девятисервисный вариант со сборщиком
из [runbook #46](cowrie-collector.md), используя отдельный тестовый project.
