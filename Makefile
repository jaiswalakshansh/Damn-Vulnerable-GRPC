# Damn Vulnerable gRPC — developer convenience Makefile
# ============================================================
# Quick reference:
#   make help           # list targets
#   make setup          # create venv + install deps + dev deps
#   make proto          # generate Python stubs from .proto files
#   make run            # run server locally
#   make up / make down # docker compose up / down
#   make test           # run pytest suite
#   make lint           # ruff + black --check
#   make format         # ruff + black --fix
#   make scoreboard     # launch the interactive progress tracker
#   make exploit N=03   # run client/exploits/exploit_03_*.py
#   make clean          # remove generated files, venv, runtime data
# ============================================================

PYTHON        ?= python3
VENV          ?= .venv
ACTIVATE      = . $(VENV)/bin/activate
DVGRPC_ROOT   ?= ./.dvgrpc
COMPOSE       ?= docker compose
HOST_PORT     ?= localhost:50051

.DEFAULT_GOAL := help

.PHONY: help
help:
	@awk 'BEGIN{FS=":.*## "} /^[a-zA-Z_-]+:.*## /{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ------------- env / deps -------------
$(VENV)/bin/python:
	$(PYTHON) -m venv $(VENV)
	$(ACTIVATE) && pip install --upgrade pip

.PHONY: setup
setup: $(VENV)/bin/python ## Create venv and install runtime + dev dependencies
	$(ACTIVATE) && pip install -r requirements.txt -r requirements-dev.txt
	@echo ""
	@echo "  Done. Activate with:  source $(VENV)/bin/activate"

.PHONY: deps
deps: ## Install runtime dependencies only
	pip install -r requirements.txt

.PHONY: deps-dev
deps-dev: ## Install dev dependencies (pytest, ruff, black)
	pip install -r requirements-dev.txt

# ------------- proto / run -------------
.PHONY: proto
proto: ## Generate Python stubs from .proto files
	mkdir -p generated && touch generated/__init__.py
	$(PYTHON) -m grpc_tools.protoc --proto_path=proto --python_out=generated --grpc_python_out=generated proto/*.proto
	@$(PYTHON) -c "import pathlib, re; \
for p in pathlib.Path('generated').glob('*_pb2_grpc.py'): \
    t = p.read_text(); \
    t = re.sub(r'^import (\\w+_pb2)', r'from generated import \\1', t, flags=re.M); \
    p.write_text(t)"
	@echo "  Stubs written to generated/"

.PHONY: run
run: ## Run the DVGRPC server locally (uses ./.dvgrpc for runtime data)
	DVGRPC_ROOT=$(DVGRPC_ROOT) $(PYTHON) -m server.main

.PHONY: reset-db
reset-db: ## Drop and rebuild the local SQLite database
	$(PYTHON) scripts/reset_db.py

# ------------- docker -------------
.PHONY: build up down logs ps shell
build: ## Build the docker image
	$(COMPOSE) build

up: ## Start the server with docker compose
	$(COMPOSE) up -d
	@echo "  Server listening on $(HOST_PORT)"

down: ## Stop the docker compose stack
	$(COMPOSE) down

logs: ## Tail server logs
	$(COMPOSE) logs -f dvgrpc

ps: ## Show compose service status
	$(COMPOSE) ps

shell: ## Shell into the running container
	$(COMPOSE) exec dvgrpc bash

# ------------- tests / lint -------------
.PHONY: test lint format
test: ## Run pytest integration tests
	DVGRPC_ROOT=$(DVGRPC_ROOT) pytest -v tests/

lint: ## Run ruff and black --check
	ruff check server/ client/ tests/ scripts/
	black --check server/ client/ tests/ scripts/

format: ## Auto-fix lint + format code
	ruff check --fix server/ client/ tests/ scripts/
	black server/ client/ tests/ scripts/

# ------------- utilities -------------
.PHONY: scoreboard enumerate exploit clean
scoreboard: ## Launch the interactive challenge tracker
	$(PYTHON) scripts/scoreboard.py

enumerate: ## List services via grpcurl (requires grpcurl on PATH)
	grpcurl -plaintext $(HOST_PORT) list

exploit: ## Run an exploit: make exploit N=03
	@test -n "$(N)" || (echo "Usage: make exploit N=03"; exit 1)
	@f=$$(ls client/exploits/exploit_$(N)_*.py 2>/dev/null | head -1); \
	  test -n "$$f" || (echo "No exploit_$(N)_*.py found"; exit 1); \
	  echo ">> $$f"; $(PYTHON) "$$f"

clean: ## Remove generated stubs, caches, and local runtime data
	rm -rf generated/ .dvgrpc/ .pytest_cache/ .ruff_cache/ **/__pycache__/
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete

clean-all: clean ## Also remove the venv
	rm -rf $(VENV)
