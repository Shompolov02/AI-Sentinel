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
REPORT_DIR ?= .artifacts
GIT_SHA ?= $(shell git rev-parse HEAD)
LOCK_SHA256 ?= $(shell (sha256sum uv.lock 2>/dev/null || shasum -a 256 uv.lock) | awk '{print $$1}')

.PHONY: bootstrap audit-metadata format format-check lint typecheck test sast sca secrets security-exceptions smoke-image container-check sbom quality

bootstrap:
	$(UV) lock --check
	$(UV) sync --all-packages --locked

audit-metadata:
	@mkdir -p $(REPORT_DIR)
	@printf '{\n  "commit": "%s",\n  "lock_file": "uv.lock",\n  "lock_sha256": "%s"\n}\n' "$(GIT_SHA)" "$(LOCK_SHA256)" > $(REPORT_DIR)/ci-metadata.json

format:
	$(RUFF) format .

format-check:
	$(RUFF) format --check .

lint:
	$(RUFF) check .

typecheck:
	$(MYPY)

test: audit-metadata
	$(PYTEST) -q --junitxml=$(REPORT_DIR)/test-results.xml --cov=ai_sentinel_smoke --cov-fail-under=80 --cov-report=term-missing --cov-report=xml:$(REPORT_DIR)/coverage.xml

sast: audit-metadata
	$(SEMGREP) scan --config p/python --config .semgrep.yml --error --exclude tests/security/fixtures --sarif --output $(REPORT_DIR)/semgrep.sarif .
	@set +e; $(SEMGREP) scan --config p/python --config .semgrep.yml --error tests/security/fixtures/semgrep-unsafe.py >/dev/null 2>&1; scan_exit=$$?; set -e; test $$scan_exit -eq 1 || (echo "Semgrep unsafe fixture was not rejected (exit $$scan_exit)" >&2; exit 1)

sca: audit-metadata
	$(UV) export --locked --no-emit-project --format requirements-txt | $(UVX) --from pip-audit==2.9.0 pip-audit --strict --format json --output $(REPORT_DIR)/pip-audit.json -r /dev/stdin

secrets:
	@command -v gitleaks >/dev/null || (echo "secrets requires gitleaks" >&2; exit 1)
	$(GITLEAKS) dir --config .gitleaks.toml --redact --no-banner --exit-code 1 .
	@set +e; $(GITLEAKS) dir --config tests/security/gitleaks-fixture.toml --redact --no-banner --exit-code 42 tests/security/fixtures >/dev/null 2>&1; scan_exit=$$?; set -e; test $$scan_exit -eq 42 || (echo "Gitleaks synthetic secret fixture was not rejected (exit $$scan_exit)" >&2; exit 1)

security-exceptions:
	$(UV) run python scripts/check_security_exceptions.py docs/security/exceptions

smoke-image: audit-metadata
	@command -v docker >/dev/null || (echo "smoke-image requires docker" >&2; exit 1)
	$(DOCKER) build --file infrastructure/docker/Dockerfile --tag $(SMOKE_IMAGE) --label org.opencontainers.image.revision=$(GIT_SHA) --label org.ai-sentinel.lock-sha256=$(LOCK_SHA256) .

container-check: smoke-image
	@command -v trivy >/dev/null || (echo "container-check requires trivy" >&2; exit 1)
	@command -v docker >/dev/null || (echo "container-check requires docker" >&2; exit 1)
	docker compose -f infrastructure/compose/smoke.yaml config --quiet
	$(TRIVY) fs --scanners vuln --format json --output $(REPORT_DIR)/trivy-fs.json --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed .
	$(TRIVY) config --format json --output $(REPORT_DIR)/trivy-config.json --exit-code 1 --severity HIGH,CRITICAL infrastructure
	@set +e; $(TRIVY) config --exit-code 42 --severity HIGH,CRITICAL tests/security/fixtures/container-policy-unsafe/Dockerfile >/dev/null 2>&1; scan_exit=$$?; set -e; test $$scan_exit -eq 42 || (echo "Trivy unsafe container-policy fixture was not rejected (exit $$scan_exit)" >&2; exit 1)
	$(TRIVY) image --scanners vuln --format json --output $(REPORT_DIR)/trivy-image.json --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed $(SMOKE_IMAGE)

sbom: smoke-image
	@command -v trivy >/dev/null || (echo "sbom requires trivy" >&2; exit 1)
	@command -v jq >/dev/null || (echo "sbom requires jq" >&2; exit 1)
	$(TRIVY) image --format cyclonedx --output $(REPORT_DIR)/sbom.raw.cdx.json $(SMOKE_IMAGE)
	@image_id="$$(docker image inspect --format '{{.Id}}' $(SMOKE_IMAGE))"; \
	image_commit="$$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' $(SMOKE_IMAGE))"; \
	image_lock="$$(docker image inspect --format '{{ index .Config.Labels "org.ai-sentinel.lock-sha256" }}' $(SMOKE_IMAGE))"; \
	jq --arg image_id "$$image_id" --arg commit "$$image_commit" --arg lock "$$image_lock" \
		'.metadata.component = ((.metadata.component // {}) + {"type":"container","name":"AI-Sentinel smoke","version":$$commit}) | .metadata.properties = ((.metadata.properties // []) + [{"name":"org.ai-sentinel.image.id","value":$$image_id},{"name":"org.ai-sentinel.commit","value":$$commit},{"name":"org.ai-sentinel.lock-sha256","value":$$lock}])' \
		$(REPORT_DIR)/sbom.raw.cdx.json > $(REPORT_DIR)/sbom.cdx.json; \
	rm $(REPORT_DIR)/sbom.raw.cdx.json; \
	jq -e --arg image_id "$$image_id" --arg commit "$(GIT_SHA)" --arg lock "$(LOCK_SHA256)" \
		'.bomFormat == "CycloneDX" and (.components | type == "array") and .metadata.component.name == "AI-Sentinel smoke" and .metadata.component.version == $$commit and any(.metadata.properties[]; .name == "org.ai-sentinel.image.id" and .value == $$image_id) and any(.metadata.properties[]; .name == "org.ai-sentinel.commit" and .value == $$commit) and any(.metadata.properties[]; .name == "org.ai-sentinel.lock-sha256" and .value == $$lock)' \
		$(REPORT_DIR)/sbom.cdx.json >/dev/null

quality:
	$(UV) lock --check
	$(MAKE) format-check
	$(RUFF) check .
	$(MYPY)
	$(PYTEST) -q --cov=ai_sentinel_smoke --cov-fail-under=80
	$(MAKE) sast
	$(MAKE) sca
	$(MAKE) secrets
	$(MAKE) security-exceptions
	$(MAKE) container-check sbom
