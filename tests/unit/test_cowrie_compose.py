from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
COMPOSE_FILE = PROJECT_ROOT / "deploy/docker-compose.yml"
INGRESS_CONFIG = PROJECT_ROOT / "deploy/cowrie-ingress.conf"
PIN = (
    "cowrie/cowrie:3.0.15@sha256:"
    "fc57120d88c2bfb5817f63f6c132ce5c2969b641c2f1ac67887652b6f294148d"
)


def test_cowrie_compose_exposes_only_isolated_loopback_listeners() -> None:
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
    cowrie = model["services"]["cowrie"]

    assert cowrie["image"] == PIN
    assert set(model["networks"]) == {"prod_net", "honeynet", "cowrie_ingress"}
    ingress = model["services"]["cowrie-ingress"]
    assert "ports" not in cowrie
    assert ingress["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": port,
            "published": str(port),
            "protocol": "tcp",
        }
        for port in (2222, 2223)
    ]
    assert list(cowrie["networks"]) == ["honeynet"]
    assert set(ingress["networks"]) == {"honeynet", "cowrie_ingress"}
    assert model["networks"]["honeynet"]["internal"] is True
    assert model["networks"]["cowrie_ingress"].get("internal", False) is False
    assert cowrie["environment"]["COWRIE_TELNET_ENABLED"] == "true"
    assert cowrie["environment"]["COWRIE_SSH_FORWARDING"] == "false"
    assert cowrie["environment"]["COWRIE_SSH_LISTEN_ENDPOINTS"].startswith("haproxy:")
    assert cowrie["environment"]["COWRIE_TELNET_LISTEN_ENDPOINTS"].startswith(
        "haproxy:"
    )
    assert cowrie["read_only"] is True
    assert cowrie["cap_drop"] == ["ALL"]
    assert cowrie["security_opt"] == ["no-new-privileges:true"]
    assert cowrie["cpus"] == 0.5
    assert cowrie["mem_limit"] == "536870912"
    assert cowrie["pids_limit"] == 100
    assert "privileged" not in cowrie
    assert "network_mode" not in cowrie
    assert "cap_add" not in cowrie
    assert all("docker.sock" not in volume["target"] for volume in cowrie["volumes"])
    assert (
        "/cowrie/cowrie-git/var:rw,noexec,nosuid,size=64m,uid=999,gid=999"
        in cowrie["tmpfs"]
    )
    assert {
        volume["source"]: volume["target"]
        for volume in cowrie["volumes"]
        if volume["type"] == "volume"
    }.items() >= {
        "cowrie-logs": "/cowrie/cowrie-git/var/log/cowrie",
        "cowrie-downloads": "/cowrie/cowrie-git/var/lib/cowrie/downloads",
        "cowrie-etc": "/cowrie/cowrie-git/etc",
        "cowrie-state": "/cowrie/cowrie-git/var/lib/cowrie",
    }.items()
    assert (
        next(
            volume for volume in cowrie["volumes"] if volume["source"] == "cowrie-etc"
        )["read_only"]
        is True
    )
    healthcheck = cowrie["healthcheck"]["test"]
    assert healthcheck[:3] == ["CMD", "/cowrie/cowrie-env/bin/python3", "-c"]
    assert "2222" in healthcheck[3]
    assert "2223" in healthcheck[3]

    assert ingress["read_only"] is True
    assert ingress["cap_drop"] == ["ALL"]
    assert ingress["security_opt"] == ["no-new-privileges:true"]
    assert ingress["depends_on"]["cowrie"]["condition"] == "service_healthy"
    assert "privileged" not in ingress
    assert "network_mode" not in ingress
    assert "cap_add" not in ingress
    assert all("docker.sock" not in volume["target"] for volume in ingress["volumes"])


def test_cowrie_tcp_ingress_forwards_only_ssh_and_telnet() -> None:
    config = INGRESS_CONFIG.read_text(encoding="utf-8")
    assert "listen 2222;" in config
    assert "listen 2223;" in config
    assert "proxy_pass cowrie:2222;" in config
    assert "proxy_pass cowrie:2223;" in config
    assert config.count("proxy_protocol on;") == 2
