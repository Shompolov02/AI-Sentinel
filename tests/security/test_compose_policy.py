"""Security policy for the normalized Phase 1 Compose model."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
COMPOSE_FILE = PROJECT_ROOT / "deploy/docker-compose.yml"
COMPOSE_DEFAULTS = {
    "BIND_ADDRESS",
    "HTTP_PORT",
    "SERVER_NAME",
    "COWRIE_SSH_PORT",
    "COWRIE_TELNET_PORT",
    "PROD_NET_SUBNET",
    "HONEYNET_SUBNET",
    "COWRIE_INGRESS_SUBNET",
}
COWRIE_PIN = (
    "cowrie/cowrie:3.0.15@sha256:"
    "fc57120d88c2bfb5817f63f6c132ce5c2969b641c2f1ac67887652b6f294148d"
)


@pytest.fixture(scope="module")
def compose_model() -> dict[str, Any]:
    docker = shutil.which("docker")
    assert docker is not None, "Compose policy requires the Docker CLI"
    clean_env = {
        key: value for key, value in os.environ.items() if key not in COMPOSE_DEFAULTS
    }
    result = subprocess.run(  # noqa: S603
        [
            docker,
            "compose",
            "--env-file",
            os.devnull,
            "-f",
            str(COMPOSE_FILE),
            "config",
            "--format",
            "json",
        ],
        cwd=PROJECT_ROOT,
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, f"Compose config failed: {result.stderr}"
    return cast(dict[str, Any], json.loads(result.stdout))


def test_all_compose_networks_have_disjoint_ipv4_cidrs(
    compose_model: dict[str, Any],
) -> None:
    expected = {
        "prod_net": ipaddress.IPv4Network("172.30.10.0/24"),
        "honeynet": ipaddress.IPv4Network("172.30.20.0/24"),
        "cowrie_ingress": ipaddress.IPv4Network("172.30.30.0/24"),
    }
    actual = {}
    for name, network in compose_model["networks"].items():
        subnets = network.get("ipam", {}).get("config", [])
        assert len(subnets) == 1, f"{name}: expected one explicit IPv4 CIDR"
        actual[name] = ipaddress.ip_network(subnets[0]["subnet"], strict=True)
        assert isinstance(actual[name], ipaddress.IPv4Network), (
            f"{name}: IPv6 CIDR forbidden"
        )
        assert network.get("enable_ipv6") is False, f"{name}: IPv6 must be disabled"
    for first_name, first_cidr in actual.items():
        for second_name, second_cidr in actual.items():
            if first_name < second_name:
                assert not first_cidr.overlaps(second_cidr), (
                    f"{first_name} and {second_name}: IPv4 CIDRs overlap"
                )
    assert actual == expected, f"Compose network CIDRs differ: {actual}"


def test_every_compose_service_declares_non_root_user(
    compose_model: dict[str, Any],
) -> None:
    expected_users = {
        "nginx": "101",
        "target-app": "10001:10001",
        "cowrie-ingress": "101",
        "cowrie": "999:999",
    }
    for name, expected_user in expected_users.items():
        actual_user = compose_model["services"][name].get("user")
        assert actual_user == expected_user, (
            f"{name}: expected non-root user {expected_user}, got {actual_user}"
        )


def test_compose_has_only_the_accepted_services_and_network_attachments(
    compose_model: dict[str, Any],
) -> None:
    expected = {
        "nginx": {"prod_net"},
        "target-app": {"prod_net"},
        "cowrie-ingress": {"honeynet", "cowrie_ingress"},
        "cowrie": {"honeynet"},
    }
    assert set(compose_model["services"]) == set(expected), "unexpected Compose service"
    assert set(compose_model["networks"]) == {
        "prod_net",
        "honeynet",
        "cowrie_ingress",
    }, "unexpected Compose network, including management_net"
    for name, networks in expected.items():
        actual = set(compose_model["services"][name]["networks"])
        assert actual == networks, f"{name}: networks {actual} differ from {networks}"
    assert compose_model["networks"]["honeynet"].get("internal") is True, (
        "honeynet must remain internal"
    )
    assert (
        compose_model["networks"]["cowrie_ingress"].get("internal", False) is False
    ), "cowrie_ingress must publish host ports"


def test_only_three_expected_tcp_ports_are_published_on_loopback(
    compose_model: dict[str, Any],
) -> None:
    expected = {
        ("nginx", "127.0.0.1", "8080", 8080, "tcp"),
        ("cowrie-ingress", "127.0.0.1", "2222", 2222, "tcp"),
        ("cowrie-ingress", "127.0.0.1", "2223", 2223, "tcp"),
    }
    actual = {
        (
            name,
            port.get("host_ip"),
            port.get("published"),
            port.get("target"),
            port.get("protocol"),
        )
        for name, service in compose_model["services"].items()
        for port in service.get("ports", [])
    }
    assert actual == expected, f"host port policy violated: {actual ^ expected}"
    for name in ("target-app", "cowrie"):
        assert not compose_model["services"][name].get("ports"), (
            f"{name}: direct host mapping forbidden"
        )


def test_every_service_drops_privileges_and_has_no_host_escape(
    compose_model: dict[str, Any],
) -> None:
    for name, service in compose_model["services"].items():
        assert service.get("cap_drop") == ["ALL"], f"{name}: cap_drop must be ALL"
        assert service.get("security_opt") == ["no-new-privileges:true"], (
            f"{name}: no-new-privileges required"
        )
        assert service.get("privileged", False) is False, (
            f"{name}: privileged forbidden"
        )
        assert not service.get("cap_add"), f"{name}: extra capabilities forbidden"
        assert service.get("network_mode") != "host", (
            f"{name}: host networking forbidden"
        )
        assert not service.get("devices"), f"{name}: device mapping forbidden"
        assert not service.get("secrets"), f"{name}: Compose secrets forbidden"
        for volume in service.get("volumes", []):
            assert "docker.sock" not in str(volume.get("source", "")), (
                f"{name}: Docker socket source forbidden"
            )
            assert "docker.sock" not in str(volume.get("target", "")), (
                f"{name}: Docker socket target forbidden"
            )


def test_read_only_services_have_only_documented_writable_paths(
    compose_model: dict[str, Any],
) -> None:
    services = compose_model["services"]
    expected_tmpfs = {
        "target-app": {"/tmp:rw,noexec,nosuid,size=64m"},  # noqa: S108
        "cowrie-ingress": {"/tmp:rw,noexec,nosuid,size=16m"},  # noqa: S108
        "cowrie": {"/cowrie/cowrie-git/var:rw,noexec,nosuid,size=64m,uid=999,gid=999"},
    }
    for name, tmpfs in expected_tmpfs.items():
        assert services[name].get("read_only") is True, f"{name}: read_only required"
        assert set(services[name].get("tmpfs", [])) == tmpfs, (
            f"{name}: tmpfs differs from documented writable path"
        )
    ingress_mounts = services["cowrie-ingress"]["volumes"]
    assert len(ingress_mounts) == 1, "cowrie-ingress: only config bind allowed"
    assert ingress_mounts[0]["type"] == "bind", "cowrie-ingress: config must be a bind"
    assert ingress_mounts[0]["target"] == "/etc/nginx/cowrie-ingress.conf"
    assert ingress_mounts[0]["read_only"] is True, (
        "cowrie-ingress: config bind must be read-only"
    )


def test_service_resources_match_phase_one_limits(
    compose_model: dict[str, Any],
) -> None:
    expected = {
        "nginx": (0.25, "134217728", 50),
        "target-app": (0.5, "536870912", 100),
        "cowrie-ingress": (0.25, "134217728", 50),
        "cowrie": (0.5, "536870912", 100),
    }
    for name, (cpus, memory, pids) in expected.items():
        service = compose_model["services"][name]
        actual = (
            service.get("cpus"),
            service.get("mem_limit"),
            service.get("pids_limit"),
        )
        assert actual == (cpus, memory, pids), (
            f"{name}: CPU/memory/PID limits {actual} differ from {(cpus, memory, pids)}"
        )


def test_healthchecks_restarts_and_healthy_dependencies(
    compose_model: dict[str, Any],
) -> None:
    services = compose_model["services"]
    for name, service in services.items():
        assert service.get("restart") == "unless-stopped", (
            f"{name}: restart must be unless-stopped"
        )
    expected_checks = {
        "nginx": ("CMD-SHELL", "/health", "8080"),
        "target-app": ("CMD", "/health", "8000"),
        "cowrie": ("CMD", "2222", "2223"),
    }
    for name, (kind, first, second) in expected_checks.items():
        check = services[name].get("healthcheck", {})
        command = check.get("test", [])
        assert command and command[0] == kind, f"{name}: healthcheck missing"
        assert first in str(command) and second in str(command), (
            f"{name}: healthcheck must probe {first} and {second}"
        )
        assert check.get("interval") == "30s", f"{name}: healthcheck interval changed"
        assert check.get("timeout") == "5s", f"{name}: healthcheck timeout changed"
        assert check.get("retries") == 3, f"{name}: healthcheck retries changed"
    assert (
        services["nginx"]["depends_on"]["target-app"]["condition"] == "service_healthy"
    ), "nginx must wait for a healthy Target App"
    assert services["cowrie-ingress"]["depends_on"]["cowrie"]["condition"] == (
        "service_healthy"
    ), "cowrie-ingress must wait for healthy Cowrie"


def test_named_volumes_have_only_expected_service_attachments(
    compose_model: dict[str, Any],
) -> None:
    expected = {
        "nginx": {"nginx-logs": ("/var/log/nginx", False)},
        "target-app": {"target-app-data": ("/app/target_app/data", False)},
        "cowrie-ingress": {},
        "cowrie": {
            "cowrie-etc": ("/cowrie/cowrie-git/etc", True),
            "cowrie-logs": ("/cowrie/cowrie-git/var/log/cowrie", False),
            "cowrie-state": ("/cowrie/cowrie-git/var/lib/cowrie", False),
            "cowrie-downloads": (
                "/cowrie/cowrie-git/var/lib/cowrie/downloads",
                False,
            ),
        },
    }
    assert set(compose_model["volumes"]) == {
        volume for attachments in expected.values() for volume in attachments
    }, "named volume declaration differs from policy"
    for name, attachments in expected.items():
        mounts = compose_model["services"][name].get("volumes", [])
        if name != "cowrie-ingress":
            assert len(mounts) == len(attachments), (
                f"{name}: extra writable mount outside documented exceptions"
            )
        actual = {
            volume["source"]: (volume["target"], volume.get("read_only", False))
            for volume in mounts
            if volume["type"] == "volume"
        }
        assert actual == attachments, (
            f"{name}: named volume attachments differ: {actual}"
        )


def test_cowrie_image_is_the_accepted_immutable_pin(
    compose_model: dict[str, Any],
) -> None:
    actual = compose_model["services"]["cowrie"].get("image")
    assert actual == COWRIE_PIN, (
        f"cowrie: immutable 3.0.15 digest required, got {actual}"
    )
    assert "v3.0.15" not in str(actual), "cowrie: nonexistent v3.0.15 tag forbidden"


def test_repository_environment_template_has_no_real_secrets() -> None:
    git = shutil.which("git")
    assert git is not None, "environment policy requires Git"
    tracked_env = subprocess.run(  # noqa: S603
        [git, "ls-files", "--error-unmatch", ".env"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tracked_env.returncode != 0, ".env must never be tracked by Git"
    example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    for key in ("LLM_API_KEY", "DEFECTDOJO_API_TOKEN", "INTERNAL_API_TOKEN"):
        assert f"{key}=\n" in example, f".env.example: {key} must be empty"
    assert "BIND_ADDRESS=127.0.0.1\n" in example, (
        ".env.example: default binding must be loopback"
    )
