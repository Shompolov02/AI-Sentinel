# Локальный стенд Фазы 1: HTTP edge

Все команды выполняются из корня проекта. Перед запуском проверьте `.env`:
`BIND_ADDRESS=127.0.0.1`, `HTTP_PORT=8080`, `SERVER_NAME=localhost`.
Подсети `PROD_NET_SUBNET=172.30.10.0/24`,
`HONEYNET_SUBNET=172.30.20.0/24` и
`COWRIE_INGRESS_SUBNET=172.30.30.0/24`, `HTTP_EDGE_SUBNET=172.30.40.0/24`
и `HTTP_INGRESS_SUBNET=172.30.50.0/24` должны не пересекаться друг с другом
и локальными сетями Docker/VPN; при конфликте задайте другие IPv4 CIDR в `.env`.
Публикация на `0.0.0.0` разрешена только в изолированной лабораторной сети.

```sh
docker compose -f deploy/docker-compose.yml config --quiet
docker compose -f deploy/docker-compose.yml up -d --build --wait
docker compose -f deploy/docker-compose.yml ps
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/docs
ssh -p 2222 synthetic@127.0.0.1
telnet 127.0.0.1 2223
```

При SSH/Telnet-проверке используйте только придуманные для лаборатории имена
и пароли. По умолчанию TCP ingress Cowrie публикуется лишь на `127.0.0.1`;
сам Cowrie не имеет host mapping и подключён только к `honeynet`. TCP ingress
имеет ровно два маршрута к Cowrie, а также отдельную `cowrie_ingress`; к
`prod_net` он не подключён. Если порты
заняты, задайте `COWRIE_SSH_PORT` и `COWRIE_TELNET_PORT` в локальном `.env`.
Порт хоста `22` не используется. HTTP порт публикует отдельный
`http-ingress`; основной Nginx и Target App остаются во внутренних сетях.
Cowrie и Target App не имеют маршрута к хосту или внешним сетям. Проверки
фактической изоляции выполняет `make test-runtime`.

Для проверки Host используйте `curl -v -H 'Host: unknown.test'
http://127.0.0.1:8080/health`: Nginx закрывает соединение без HTTP-ответа.
Структурированный access log доступен через
`docker compose -f deploy/docker-compose.yml exec nginx cat /var/log/nginx/access.log`;
логи Target App — через `docker compose -f deploy/docker-compose.yml logs target-app`.
Один `X-Request-ID` связывает HTTP-ответ и обе записи журналов.

Cowrie хранит сырые JSON-события в `cowrie-logs`. В distroless-образе нет
shell или `cat`, поэтому прочитать журнал можно встроенным Python:

```sh
docker compose -f deploy/docker-compose.yml exec -T cowrie /cowrie/cowrie-env/bin/python3 -c 'from pathlib import Path; print(Path("var/log/cowrie/cowrie.json").read_text())'
```

Downloads хранятся в `cowrie-downloads`, UUID и SSH host keys — в
`cowrie-state`; `cowrie-etc` содержит встроенные файлы конфигурации образа и
монтируется только для чтения. Остальное временное состояние Cowrie хранится
в tmpfs. Проверьте фактический health status командой
`docker compose -f deploy/docker-compose.yml ps` — он зависит от обоих
listener, SSH и Telnet.

```sh
make test-runtime
make test
make quality
make acceptance
docker compose -f deploy/docker-compose.yml down
```

`down` сохраняет все named volumes, включая журналы, загрузки и состояние
Cowrie. Для удаления синтетических данных и журналов после остановки
**явно** используйте `docker compose -f deploy/docker-compose.yml down -v`.
