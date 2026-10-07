# Single entry point for humans, agents, and CI. CI calls the same targets.

INTEGRATION_SERVER := Tools/integration-server
SWIFT_FORMAT_PATHS := $(wildcard Sources Tests Package.swift)

.PHONY: setup format lint build test check integration docs

setup:
	git config core.hooksPath .githooks

format:
	swift format format --in-place --recursive --parallel $(SWIFT_FORMAT_PATHS)

lint:
	swift format lint --strict --recursive --parallel $(SWIFT_FORMAT_PATHS)
	scripts/check-determinism.sh

build:
	swift build --build-tests

test:
	swift test --parallel

check: lint build test
	@echo "make check: all checks passed"

# Runs the integration tests against the local server in Tools/integration-server (needs Node.js and, on the
# first run, network access for `npm ci`). Not part of `check`.
integration:
	@set -e; \
	[ -d $(INTEGRATION_SERVER)/node_modules ] || npm ci --prefix $(INTEGRATION_SERVER); \
	port=$$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'); \
	log=$$(mktemp); \
	(cd $(INTEGRATION_SERVER) && PORT=$$port ACCESS_TOKEN_TTL=60 REFRESH_TOKEN_TTL=3600 exec node server.js >"$$log" 2>&1) & \
	pid=$$!; \
	trap 'kill $$pid 2>/dev/null || true; rm -f "$$log"' EXIT; \
	issuer=http://localhost:$$port; \
	ready=; for _ in $$(seq 1 50); do \
		curl -sf "$$issuer/.well-known/oauth-authorization-server" >/dev/null && ready=yes && break; sleep 0.2; \
	done; \
	[ -n "$$ready" ] || { echo "integration server did not start:"; cat "$$log"; exit 1; }; \
	status=0; \
	PASSPORTKIT_INTEGRATION_ISSUER=$$issuer swift test --filter IntegrationTests || status=$$?; \
	exit $$status
