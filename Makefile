# sre-es — MCP server. All Python commands run through uv.
IMAGE ?= sre-es
TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
URL ?= http://localhost:8080/mcp
ENV_FILE ?= .env.deploy
CONTAINER ?= $(IMAGE)-mcp
NETWORK ?= msb-mcp-net
PUBLISH ?=
EDGE ?= msb-caddy
EDGE_HOST ?= 116-118-92-80.nip.io

.PHONY: setup dev test lint fmt lock tools call inspector docker-build docker-run deploy undeploy logs edge edge-logs

setup:            ## Install deps and create .env (local, MCP_AUTH_MODE=none) if missing
	uv sync
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example")

dev:              ## Run the server locally on :8080 (MCP endpoint /mcp)
	uv run python server.py

test:             ## End-to-end tests (real server + real MCP client)
	uv run pytest -q

lint:
	uv run ruff check . && uv run ruff format --check .

fmt:
	uv run ruff check --fix . && uv run ruff format .

lock:             ## Update uv.lock after changing dependencies
	uv lock

tools:            ## List tools of the running server (TOKEN=<api key | JWT> if auth is on)
	MCP_URL=$(URL) MCP_TOKEN=$(TOKEN) uv run python scripts/call_tool.py

call:             ## Call a tool: make call TOOL=get_overview   |   make call TOOL=search_logs ARGS='{"start":"now-1h"}'
	MCP_URL=$(URL) MCP_TOKEN=$(TOKEN) uv run python scripts/call_tool.py $(TOOL) '$(or $(ARGS),{})'

inspector:        ## Interactive UI — connect with Streamable HTTP to $(URL)
	npx @modelcontextprotocol/inspector

docker-build:     ## Build a linux/amd64 image for AgentBase Runtime
	docker build --platform linux/amd64 -t $(IMAGE):$(TAG) .

docker-run:       ## Run the image locally with .env
	docker run --rm -p 8080:8080 --env-file .env $(IMAGE):$(TAG)

deploy:           ## Build and (re)start the MCP container on $(NETWORK), detached, env from $(ENV_FILE). Not published: reached through `make edge`. Restarts on reboot
	docker build --platform linux/amd64 -t $(IMAGE):$(TAG) .
	-docker network create $(NETWORK)
	-docker rm -f $(CONTAINER)
	docker run -d --name $(CONTAINER) --network $(NETWORK) --restart unless-stopped $(PUBLISH) \
		--log-opt max-size=10m --log-opt max-file=3 \
		--add-host=host.docker.internal:host-gateway --env-file $(ENV_FILE) $(IMAGE):$(TAG)

undeploy:         ## Stop and remove the deployed MCP container
	docker rm -f $(CONTAINER)

logs:             ## Follow the deployed MCP container's logs
	docker logs -f --tail 100 $(CONTAINER)

edge:             ## (Re)start the Caddy TLS front door: https://$(EDGE_HOST) -> $(CONTAINER):8080 (Let's Encrypt cert, auto-renewed; needs ports 80+443 open)
	-docker network create $(NETWORK)
	-docker rm -f $(EDGE)
	docker run -d --name $(EDGE) --network $(NETWORK) --restart unless-stopped -p 80:80 -p 443:443 \
		-e EDGE_HOST=$(EDGE_HOST) -v $(CURDIR)/edge/Caddyfile:/etc/caddy/Caddyfile:ro \
		-v caddy_data:/data -v caddy_config:/config \
		--log-opt max-size=10m --log-opt max-file=3 caddy:2

edge-logs:        ## Follow the Caddy container's logs
	docker logs -f --tail 100 $(EDGE)
