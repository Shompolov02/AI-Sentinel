# Локальный стенд Фазы 1: HTTP edge

Все команды выполняются из корня проекта. Перед запуском проверьте `.env`:
`BIND_ADDRESS=127.0.0.1`, `HTTP_PORT=8080`, `SERVER_NAME=localhost`.
Публикация на `0.0.0.0` разрешена только в изолированной лабораторной сети.

```sh
docker compose -f deploy/docker-compose.yml config --quiet
docker compose -f deploy/docker-compose.yml up -d --build --wait
docker compose -f deploy/docker-compose.yml ps
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/docs
```

Для проверки Host используйте `curl -v -H 'Host: unknown.test'
http://127.0.0.1:8080/health`: Nginx закрывает соединение без HTTP-ответа.
Структурированный access log доступен через
`docker compose -f deploy/docker-compose.yml exec nginx cat /var/log/nginx/access.log`;
логи Target App — через `docker compose -f deploy/docker-compose.yml logs target-app`.
Один `X-Request-ID` связывает HTTP-ответ и обе записи журналов.

```sh
make test-runtime
make quality
docker compose -f deploy/docker-compose.yml down
```

`down` сохраняет named volumes. Для удаления синтетических данных и журналов
после остановки используйте `docker compose -f deploy/docker-compose.yml down -v`.
