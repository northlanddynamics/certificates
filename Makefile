# Local development: `make dev` brings up Postgres, Pebble and BIND (Docker), installs dependencies, writes a .env on
# first use, and runs the API (:3000) and the web UI (:5173) together. Compatible with the GNU Make 3.81 that macOS ships.

COMPOSE   ?= docker compose
SERVICES  ?= postgres pebble pebble-eab bind
WEB_PORT  ?= 5173
API_PORT  ?= 3000

# The local Agent's binary and state (its credential, and the keys it makes) live under .dev/, which is not committed.
# It talks to the API over plain HTTP: an Agent allows that for a loopback address only (ADR 0006).
DEV_DIR        := .dev
AGENT_BIN      := $(DEV_DIR)/bin/agent
AGENT_STATE    := $(DEV_DIR)/agent-state
AGENT_PLATFORM ?= http://localhost:$(API_PORT)
AGENT_FLAGS    := --state-dir $(AGENT_STATE)

.PHONY: help setup dev server web install env infra down migrate creds status logs test check clean \
	agent-build agent-test agent-register agent-run agent-reset

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{ printf "  make %-15s %s\n", $$1, $$2 }'

setup: install env infra ## Install dependencies, write .env, start the Docker services (no app servers)

dev: setup ## Set everything up, then run the API and the web UI together (Ctrl-C stops both)
	@echo ""
	@echo "  Web UI    http://localhost:$(WEB_PORT)"
	@echo "  API docs  http://localhost:$(API_PORT)/api/docs"
	@echo "  Operator  see 'make creds'"
	@echo ""
	@trap 'trap - INT TERM EXIT; kill 0' INT TERM EXIT; \
		bun run dev:server & \
		bun run dev:web & \
		wait

server: install env infra ## Run only the API (:3000), applying migrations on start
	bun run dev:server

web: install ## Run only the web UI (:5173); it proxies /api to :3000
	bun run dev:web

# Reinstall when a manifest or the lockfile is newer than the last install.
install: node_modules/.installed ## Install dependencies (root and web/ workspace)
node_modules/.installed: package.json bun.lock web/package.json
	bun install
	@touch $@

# .env is read by Bun from the repo root, so the server and `make migrate` need no exports. Variables already set in
# your shell take precedence. It is written once and kept: LOCAL_KMS_KEY wraps each Organization's data key, so a
# new one would make the stored secrets in an existing database unreadable.
env: .env ## Write .env with generated secrets, if it does not exist
.env:
	@command -v openssl >/dev/null || { echo "openssl is required to generate secrets"; exit 1; }
	@printf '%s\n' \
		'DATABASE_URL=postgres://postgres:postgres@localhost:5433/certs' \
		"AUTH_SECRET=$$(openssl rand -hex 32)" \
		"LOCAL_KMS_KEY=$$(openssl rand -base64 32)" \
		'WEB_URL=http://localhost:$(WEB_PORT)' \
		'TRUSTED_ORIGINS=http://localhost:$(WEB_PORT)' \
		'OPERATOR_EMAIL=operator@example.com' \
		"OPERATOR_PASSWORD=$$(openssl rand -hex 12)" \
		> $@
	@echo "wrote .env"

infra: ## Start Postgres (:5433), Pebble (:14000, and :14001 with EAB required) and BIND (:5354), and wait until they are up
	@docker info >/dev/null 2>&1 || { echo "Docker is not running"; exit 1; }
	$(COMPOSE) up -d --wait $(SERVICES)

down: ## Stop the Docker services (data is kept)
	$(COMPOSE) down

migrate: env ## Apply database migrations without starting the server
	bun run migrate

creds: env ## Show the Platform Operator's email and password from .env
	@grep -E '^OPERATOR_(EMAIL|PASSWORD)=' .env | sed 's/^OPERATOR_/  /; s/=/: /'

status: ## Show the Docker services
	$(COMPOSE) ps

logs: ## Follow the Docker services' logs
	$(COMPOSE) logs -f

test: infra ## Run the server tests (they use the certs_test database, and build micromdm's SCEP client to run)
	$(COMPOSE) build scepclient
	bun run test

check: ## Typecheck the server and the web app
	bun run typecheck

clean: ## Stop the Docker services, delete their data, .env and the local Agent (a full reset)
	$(COMPOSE) down -v
	rm -rf .env node_modules/.installed $(DEV_DIR)

# The local Agent. Run the platform first (`make dev`), then:
#   make agent-register TOKEN=agt_...   once, with a token an Organization Administrator makes on the Agents page
#   make agent-run                      then, in its own terminal
agent-build: ## Build the Agent into .dev/bin/agent
	cd agent && go build -o ../$(AGENT_BIN) ./cmd/agent

agent-test: ## Vet and test the Agent (Seam B, against a stub platform)
	cd agent && go vet ./... && go test ./...

agent-register: ## Register the local Agent with the platform: make agent-register TOKEN=agt_...
	@test -n "$(TOKEN)" || { echo "usage: make agent-register TOKEN=agt_...  (an Organization Administrator makes the token on the Agents page)"; exit 1; }
	@test -z "$$(ls -A $(AGENT_STATE) 2>/dev/null)" || { echo "this Agent is already registered; 'make agent-reset' forgets it"; exit 1; }
	@$(MAKE) --no-print-directory agent-build
	AGENT_REGISTRATION_TOKEN='$(TOKEN)' $(AGENT_BIN) register $(AGENT_FLAGS) --platform $(AGENT_PLATFORM)

agent-run: ## Run the registered Agent (Ctrl-C stops it); needs the API running
	@test -n "$$(ls -A $(AGENT_STATE) 2>/dev/null)" || { echo "no Agent is registered here: make agent-register TOKEN=agt_..."; exit 1; }
	@$(MAKE) --no-print-directory agent-build
	$(AGENT_BIN) run $(AGENT_FLAGS)

agent-reset: ## Forget the local Agent (its credential and any keys it made); register again with a new token
	rm -rf $(AGENT_STATE)
