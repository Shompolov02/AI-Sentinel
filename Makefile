.DEFAULT_GOAL := quality

UV ?= uv
UVX ?= uvx
RUFF := $(UV) run ruff
MYPY := $(UV) run mypy
PYTEST := $(UV) run pytest

.PHONY: bootstrap format lint typecheck test sast sca secrets container-check quality

bootstrap:
	$(UV) sync --all-packages --locked

format:
	$(RUFF) format .

lint:
	$(RUFF) check .

typecheck:
	$(MYPY)

test:
	$(PYTEST) -q --cov=ai_sentinel_smoke --cov-fail-under=1

sast:
	$(UVX) --from semgrep==1.136.0 --with 'setuptools<81' semgrep scan --config p/python --error .

sca:
	$(UV) export --locked --no-emit-project --format requirements-txt | $(UVX) --from pip-audit==2.9.0 pip-audit --strict -r /dev/stdin

secrets:
	@command -v gitleaks >/dev/null || (echo "secrets requires gitleaks" >&2; exit 1)
	gitleaks dir --redact --no-banner --exit-code 1 .

container-check:
	@command -v trivy >/dev/null || (echo "container-check requires trivy" >&2; exit 1)
	trivy config --exit-code 1 infrastructure

quality:
	$(UV) lock --check
	$(RUFF) format --check .
	$(RUFF) check .
	$(MYPY)
	$(PYTEST) -q --cov=ai_sentinel_smoke --cov-fail-under=1
	$(MAKE) sast
	$(MAKE) sca
	$(MAKE) secrets
	$(MAKE) container-check