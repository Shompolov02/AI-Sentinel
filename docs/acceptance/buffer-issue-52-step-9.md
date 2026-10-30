# #52: пункт 9 — эксплуатационная и security-приёмка

Проверки: 2026-10-28–29. Ветка `codex/issue-52-buffer`, база
`e61d17bfdac683ebf138dd7d13564718e186b857`. После `git fetch origin main`
HEAD, локальный main и origin/main совпали. Изменения остаются незакоммиченными;
публикация PR относится к пункту 10, merge выполняет владелец.

## Проверки

```sh
make quality
CORE_GUARD_MODEL_DIR="$PWD/.local/prompt-guard/model" \
  AI_SENTINEL_REQUIRE_GUARD=1 make test-runtime
```

В первом полном прогоне `AI_SENTINEL_RUNTIME_REUSE_IMAGES` не задан. Runtime запускается
последовательно; зависимости и модель закреплены проектом. Повтор последнего
сценария с проверенными текущими образами описан ниже.

| Проверка | Результат |
| --- | --- |
| `make quality` | passed; 197 обычных тестов, 27 runtime deselected |
| Финальный `make test` | 197 passed за 62,13 с; JUnit: 0 failures/errors/skips |
| Ruff / format / mypy | passed; финально 118 форматируемых файлов, 60 файлов mypy |
| Smoke coverage | 100%; относится только к smoke-пакету |
| Semgrep, полный gate | passed; два прежних inSource suppression учебного Target App |
| Semgrep явно по всему Core с `--no-git-ignore` | 21 модуль, 152 правила, 0 находок |
| pip-audit | 50 зависимостей, 0 известных уязвимостей |
| Gitleaks и проверка security exceptions | passed; новых исключений/подавлений нет |
| Trivy fs / config / четыре свежих image | 0 блокирующих HIGH/CRITICAL по политике проекта |
| CycloneDX SBOM | создан и проверен с image ID, базовым commit и SHA uv.lock |
| Первый полный runtime с обязательным Guard | 26 passed, 1 timeout |
| Retention/Guard: диагностический повтор | 1 passed за 187,20 с |
| Retention/Guard: чистый повтор без трассировки | 1 passed за 216,07 с |
| Второй полный runtime до исправления harness | 25 passed, 2 failed |
| Два затронутых сценария после исправления harness | 2 passed за 734,07 с |
| Полный runtime на окончательных тестах | **27 passed, 197 deselected**, без пропусков/ошибок, 944,77 с |

Команда успешного заключительного runtime-прогона:

```sh
CORE_GUARD_MODEL_DIR="$PWD/.local/prompt-guard/model" \
  AI_SENTINEL_REQUIRE_GUARD=1 AI_SENTINEL_RUNTIME_REUSE_IMAGES=1 \
  caffeinate -i -m -s make test-runtime
```

Сборка Core, Guard и collector из текущего дерева прошла штатно в начале
приёмки. Повторная сборка позже столкнулась с TLS timeout Docker Hub;
сохранённые результаты и режим повторного запуска описаны ниже.
SHA-256 всех 21 Python-модулей внутри трёх
runtime-образов совпали с workspace. Все пять файлов локальной модели
совпали с закреплёнными SHA-256; загрузка новых весов не понадобилась.
Внешняя LLM не вызывается.

### Неуспешные запуски и диагностика

Первый полный прогон: 26 passed, 1 failed за 1211,17 с. Последний retention/Guard
тест не дождался терминального состояния первой команды за 180 с. Core всё же
записал `prompt_injection_detected` для этой команды; доставка не потеряна.
Отдельный повтор завершился HTTP ReadTimeout за 228,71 с на том же этапе.
В журнале macOS подтверждены многократные `Clamshell Sleep`/пробуждения во время
этих запусков, с большими временными разрывами в контейнерных журналах.
Прогоны с паузами хоста не считаются успешной эксплуатационной приёмкой.

После пробуждения два повтора остановились до запуска стенда: Docker Hub
вернул TLS handshake timeout при проверке metadata Nginx base image.
В retention-harness добавлен общий с остальными тестами opt-in
`AI_SENTINEL_RUNTIME_REUSE_IMAGES=1`; по умолчанию остаётся `--build`.
Повтор использует уже собранные в этом пункте образы с повторно проверенными
SHA исходников и временный `caffeinate` только на время теста. Timeout и
проверяемое поведение не ослаблены; production-код после quality не менялся.

После добавления opt-in режим прошёл диагностический запуск с временными
стеками, затем чистый повтор без трассировки. Стеки сохранены отдельно;
временный `faulthandler` полностью удалён. Устойчивый дефект в production-коде
не локализован; отдельные HTTP ReadTimeout не приписываются доказанно только
сну хоста. Затем повторён весь runtime-набор с обязательным Guard и теми же
проверенными образами, чтобы подтвердить совокупный результат.

Второй полный прогон дал 25 passed / 2 failed. Помимо повторной задержки первой
retention-команды, старый Core/Cowrie-тест сравнил разные наблюдения доступности
raw-reader. Traceback показал одинаковые остальные девять частей ответа;
различалась Evidence с динамическим `source_status`, а не результат анализа.
Теперь исходные и повторные полные снимки сравниваются после подтверждённого
`available`. Ожидание ограничено 60 с; `deleted`, неожиданные HTTP-коды или
невосстановившийся источник по-прежнему приводят к ошибке. Полное равенство
вердикта, анализа, Evidence, истории и аудита после replay/restart сохранено.

Retention-harness опрашивает список/карточки раз в секунду вместо 250 мс:
каждая авторизованная карточка также обращается к reader через TLS и SQLite.
Общий deadline 180 с и все утверждения по Guard, файлам и срокам сохранены.
После этих изменений оба сценария прошли последовательным запуском.
Снимок среды: Mac 8 GiB RAM, около 14,9 GiB использованного swap, Docker VM
около 4 GiB; дочерний Guard наблюдался в I/O wait. Это ограничения среды
измерения, а не введённые продуктовые SLO. Единственная причина всех прежних
задержек не установлена; снижение нагрузки опроса подтверждено успешным прогоном,
но не объявляется исправлением доказанного production-дефекта.

## Соответствие AC и runbook

- AC1: ограничения Core/outbox/chunks, warning → slowdown → stopped → resumed,
  нехватка места, сохранность курсора и восстановление после restart покрыты
  HTTP-тестами и настоящим collector/Fluent Bit. Потеря ответа после commit
  Core проверяется повтором без второй задачи и повторного анализа.
- AC2: граница 14 суток проверяется управляемыми часами, без смены часов хоста.
  Удаляются payload и chunks, включая ранее открытый inode; свежие записи
  сохраняются. Commit/logging/физические отказы дают проверяемое восстановление.
  Непринятые записи не создают задач или веб-тревог.
- AC3: отдельный Compose project проходит настоящий Cowrie SSH/Telnet →
  Fluent Bit → проверенный TLS → Core, наблюдает переполнение и истечение,
  проверяет прежние DNS/IP-ограничения и живую Telnet-сессию.

Команды config/up/CLI, проверка readiness, файлов, прав и hardening,
пересоздание сервисов и project-scoped cleanup выполняются harness на своих
credentials, временных файлах и named volumes. Пользовательский стенд не
используется как фикстура. Отдельные ML/Core и retention-сценарии проверяют
полный набор overlays, реальные закреплённые веса, reader, replay,
14/30-дневное удаление и продолжение сессий Cowrie.

Дополнительно на живом тестовом project выполнены команды `stat` из runbook:
collector `/data` = `2770 10001:999`, база и registry/owner locks =
`0660 10001:999`; Core `/data` = `0700 10001:10001`. Проверен Docker-журнал
Cowrie с локальным `json-file`: stdout/stderr пусты после входов и команд.
В доказательство сохранены длины и hash, без текста журналов.

Обновлены README, локальный игнорируемый CONTEXT.md, контракт буфера и runbooks
collector/retention. При обновлении пересоздаются также retention и core-intake:
они должны получить общий бюджет/lease и разрешить авторизованный HEAD через
прежний TLS. Право очистки reader или Cowrie не выдаётся.

## Границы гарантий

64 MiB payload и 64 MiB chunks не ограничивают весь том. Исходные журналы,
SQLite и метаданные требуют контроля места. Динамический запас не резервирует
блоки и не защищает от внешнего writer. Выключенный или недоступный носитель
физически очистить нельзя; отказ сохраняет намерение, а не считается успехом.
Сигнал об истечении следует за commit и может повториться после сбоя; он сам
по себе не доказывает очистку chunks или exactly-once внешнего logging driver.
При потерянном ответе Core задача уже может существовать. Численные SLO
производительности и внешние интеграции этот срез не устанавливает.

## Доказательства

- `.artifacts/issue52-step9-quality.log` и `issue52-step9-quality/` — полный gate,
  security reports и SBOM.
- `.artifacts/issue52-step9-core-semgrep.log` / `.sarif` — явная проверка Core.
- `.artifacts/issue52-step9-build-{core,guard,collector}.log` и
  `issue52-step9-image-source.json` — сборка и сравнение исходников внутри image.
- `.artifacts/issue52-step9-runtime-collection.txt` / `issue52-step9-runtime.log`
  — состав и результат первого полного runtime-набора;
  `issue52-step9-final-runtime.log` — второй полный прогон до исправления harness;
  `issue52-step9-verified-runtime.log` — прогон окончательных тестов.
- `.artifacts/issue52-step9-retention-{recheck,awake,final,local,stacks,clean}.log`,
  `issue52-step9-retention-{red-logs,stacks-details}.txt` и
  `issue52-step9-host-sleep.txt` — неуспешные и успешные повторы, диагностика.
- `.artifacts/issue52-step9-final-static.log` и
  `issue52-step9-final-image-source.json` — финальные статические проверки и
  повторное сравнение исходников в runtime images.
- `.artifacts/issue52-step9-ml-cadence.log`, `issue52-step9-vm-pressure.txt` и
  `issue52-step9-verified-static.log` — два затронутых сценария после исправления
  harness, измерения среды и статические проверки окончательных тестов.
- `.artifacts/issue52-step9-final-test.log` и `issue52-step9-final-test/` —
  заключительные 197 тестов, JUnit/coverage и повторная проверка secrets/exceptions.
- `.artifacts/issue52-step9-runbook-permissions.json` и
  `issue52-step9-cowrie-stdout.json` — дополнительные команды runbook.
- `.artifacts/issue52-step9-source-sha256.json` — 201 файл на старте гейтов,
  включая игнорируемый CONTEXT.md; три исходных пользовательских untracked-файла
  исключены и проверяются отдельно.
- `.artifacts/issue52-step9-tested-source-sha256.json` — 202 файла окончательной
  версии тестов на старте успешного полного прогона; при завершении все hashes
  совпали. Последующая правка касается только итоговой документации.
- `.artifacts/issue52-step9-final-source-sha256.json` — окончательный манифест
  после заполнения отчёта; `issue52-step9-cleanup.json` — проверка Docker cleanup.

Предыдущие red → green доказательства сохранены в отчётах
[пункта 6](buffer-issue-52-step-6.md), [пункта 7](buffer-issue-52-step-7.md)
и [пункта 8](buffer-issue-52-step-8.md).

## Итог

Пункт 9 завершён: 197 обычных тестов, полный quality/security gate и итоговый
единый runtime-прогон 27/27 прошли. Pytest сохраняет одно прежнее предупреждение
Starlette/httpx; это не пропуск. Все AC #52 и связанные runbook-проверки подтверждены
на отдельных тестовых данных. После тестов нет запущенных контейнеров и тестовых
сетей/именованных томов; четыре прежних анонимных тома 2024/2026-10-08 не затронуты.
Три исходных пользовательских untracked-файла совпали с начальными SHA-256.
Далее — пункт 10: коммит, push и PR в main; merge остаётся владельцу.
