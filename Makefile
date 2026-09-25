.DEFAULT_GOAL := quality

UV ?= uv
UVX ?= uvx
RUFF := $(UV) run ruff
MYPY := $(UV) run mypy
PYTEST := $(UV) run pytest
SEMGREP := $(UVX) --from semgrep==1.136.0 --with 'setuptools<81' semgrep
GITLEAKS ?= gitleaks
TRIVY ?= trivy
DOCKER ?= docker
SMOKE_IMAGE ?= ai-sentinel-smoke:security-scan

.PHONY: bootstrap format format-check lint typecheck test sast sca secrets container-check quality

bootstrap:
	$(UV) sync --all-packages --locked

format:
	$(RUFF) format .

format-check:
	$(RUFF) format --check .

lint:
	$(RUFF) check .

typecheck:
	$(MYPY)

test:
	$(PYTEST) -q --cov=ai_sentinel_smoke --cov-fail-under=80

sast:
	$(SEMGREP) scan --config p/python --config .semgrep.yml --error --exclude tests/security/fixtures .
	@set +e; $(SEMGREP) scan --config p/python --config .semgrep.yml --error tests/security/fixtures/semgrep-unsafe.py >/dev/null 2>&1; scan_exit=$$?; set -e; test $$scan_exit -eq 1 || (echo "Semgrep unsafe fixture was not rejected (exit $$scan_exit)" >&2; exit 1)

sca:
	$(UV) export --locked --no-emit-project --format requirements-txt | $(UVX) --from pip-audit==2.9.0 pip-audit --strict -r /dev/stdin

secrets:
	@command -v gitleaks >/dev/null || (echo "secrets requires gitleaks" >&2; exit 1)
	$(GITLEAKS) dir --config .gitleaks.toml --redact --no-banner --exit-code 1 .
	@set +e; $(GITLEAKS) dir --config tests/security/gitleaks-fixture.toml --redact --no-banner --exit-code 42 tests/security/fixtures >/dev/null 2>&1; scan_exit=$$?; set -e; test $$scan_exit -eq 42 || (echo "Gitleaks synthetic secret fixture was not rejected (exit $$scan_exit)" >&2; exit 1)

container-check:
	@command -v trivy >/dev/null || (echo "container-check requires trivy" >&2; exit 1)
	@command -v docker >/dev/null || (echo "container-check requires docker" >&2; exit 1)
	docker compose -f infrastructure/compose/smoke.yaml config --quiet
	$(TRIVY) fs --scanners vuln --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed .
	$(TRIVY) config --exit-code 1 --severity HIGH,CRITICAL infrastructure
	@set +e; $(TRIVY) config --exit-code 42 --severity HIGH,CRITICAL tests/security/fixtures/container-policy-unsafe/Dockerfile >/dev/null 2>&1; scan_exit=$$?; set -e; test $$scan_exit -eq 42 || (echo "Trivy unsafe container-policy fixture was not rejected (exit $$scan_exit)" >&2; exit 1)
	$(DOCKER) build --file infrastructure/docker/Dockerfile --tag $(SMOKE_IMAGE) .
	$(TRIVY) image --scanners vuln --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed $(SMOKE_IMAGE)

quality:
	$(UV) lock --check
	$(MAKE) format-check
	$(RUFF) check .
	$(MYPY)
	$(PYTEST) -q --cov=ai_sentinel_smoke --cov-fail-under=80
	$(MAKE) sast
	$(MAKE) sca
	$(MAKE) secrets
	$(MAKE) container-check