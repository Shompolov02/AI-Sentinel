from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
COMPOSE_FILE = PROJECT_ROOT / "deploy/docker-compose.yml"
NGINX_TEMPLATE = PROJECT_ROOT / "deploy/nginx/default.conf.template"
HTTP_INGRESS_CONFIG = PROJECT_ROOT / "deploy/http-ingress.conf"


def test_compose_exposes_only_http_ingress_on_loopback() -> None:
    docker = shutil.which("docker")
    assert docker is not None
    result = subprocess.run(  # noqa: S603
        [docker, "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    model = json.loads(result.stdout)
    nginx = model["services"]["nginx"]
    ingress = model["services"]["http-ingress"]
    target = model["services"]["target-app"]

    assert "ports" not in nginx
    assert ingress["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8080,
            "published": "8080",
            "protocol": "tcp",
        }
    ]
    assert "ports" not in target
    assert set(nginx["networks"]) == {"prod_net", "http_edge"}
    assert set(ingress["networks"]) == {"http_edge", "http_ingress"}
    assert list(target["networks"]) == ["prod_net"]
    assert list(model["services"]["cowrie"]["networks"]) == ["honeynet"]
    assert model["services"]["cowrie"]["healthcheck"]["test"][:2] == [
        "CMD",
        "/cowrie/cowrie-env/bin/python3",
    ]
    assert nginx["environment"]["SERVER_NAME"] == "localhost"
    assert target["environment"]["TRUST_NGINX_HEADERS"] == "1"
    assert any(
        volume["source"] == "nginx-logs" and volume["type"] == "volume"
        for volume in nginx["volumes"]
    )


def test_nginx_template_has_host_boundary_and_json_access_log() -> None:
    config = NGINX_TEMPLATE.read_text(encoding="utf-8")

    assert "listen 8080 default_server" in config
    assert "return 444" in config
    assert "server_name localhost 127.0.0.1 ${SERVER_NAME}" in config
    assert "proxy_pass http://target-app:8000" in config
    assert "proxy_set_header X-Request-ID $request_id" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr" in config
    assert 'proxy_set_header Forwarded ""' in config
    assert "escape=json" in config
    assert "access_log /var/log/nginx/access.log" in config
    assert "server_tokens off" in config
    assert "set_real_ip_from ${HTTP_EDGE_SUBNET};" in config
    assert "real_ip_header proxy_protocol;" in config


def test_http_ingress_forwards_only_to_nginx_with_client_address() -> None:
    config = HTTP_INGRESS_CONFIG.read_text(encoding="utf-8")
    assert config.count("proxy_pass ") == 1
    assert "proxy_pass nginx:8080;" in config
    assert "proxy_protocol on;" in config
