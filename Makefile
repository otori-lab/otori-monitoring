# ═══════════════════════════════════════════════════════════════════════════════
# Otori Monitoring - Makefile
# ═══════════════════════════════════════════════════════════════════════════════

.PHONY: help install dev run stream test lint format clean \
        up down logs build ps shell db-shell reset

# Default
.DEFAULT_GOAL := help

# ───────────────────────────────────────────────────────────────────────────────
# Variables
# ───────────────────────────────────────────────────────────────────────────────
DC := docker compose -f docker/docker-compose.yml
DC_DEV := $(DC) -f docker/docker-compose.dev.yml

# ───────────────────────────────────────────────────────────────────────────────
# Help
# ───────────────────────────────────────────────────────────────────────────────
help: ## Affiche cette aide
	@echo ""
	@echo "  ██████╗ ████████╗ ██████╗ ██████╗ ██╗"
	@echo " ██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗██║"
	@echo " ██║   ██║   ██║   ██║   ██║██████╔╝██║"
	@echo " ██║   ██║   ██║   ██║   ██║██╔══██╗██║"
	@echo " ╚██████╔╝   ██║   ╚██████╔╝██║  ██║██║"
	@echo "  ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝"
	@echo ""
	@echo "  Monitoring v2.0"
	@echo ""
	@echo "  \033[1mLocal Development\033[0m"
	@grep -E '^(install|dev|run|stream|test|lint|format|clean):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  \033[1mDocker\033[0m"
	@grep -E '^(up|down|build|logs|ps|shell|db-shell|reset|prod):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ───────────────────────────────────────────────────────────────────────────────
# Local Development
# ───────────────────────────────────────────────────────────────────────────────
install: ## Installe les dépendances
	uv pip install -e .

dev: ## Installe les dépendances dev
	uv pip install -e ".[dev]"

run: ## Lance le serveur local (SQLite)
	uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

stream: ## Lance le streamer Cowrie
	uv run python -m tools.stream_cowrie_file

test: ## Lance les tests
	uv run pytest tests/ -v

lint: ## Vérifie le code (ruff)
	uv run ruff check app/ tools/ tests/

lint-fix: ## Corrige le lint
	uv run ruff check app/ tools/ tests/ --fix

format: ## Formate le code
	uv run ruff format app/ tools/ tests/

clean: ## Nettoie les fichiers temp
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -f .coverage coverage.xml 2>/dev/null || true

# ───────────────────────────────────────────────────────────────────────────────
# Docker Commands
# ───────────────────────────────────────────────────────────────────────────────
build: ## Build les images
	$(DC) build

up: ## Démarre les containers (PostgreSQL + API)
	$(DC) up -d

down: ## Arrête les containers
	$(DC) down

logs: ## Affiche les logs (tous)
	$(DC) logs -f

logs-api: ## Affiche les logs API
	$(DC) logs -f api

logs-db: ## Affiche les logs DB
	$(DC) logs -f db

ps: ## Statut des containers
	$(DC) ps

shell: ## Shell dans le container API
	$(DC) exec api /bin/bash

db-shell: ## Shell PostgreSQL
	$(DC) exec db psql -U otori -d otori

reset: ## Reset complet (supprime les volumes)
	$(DC) down -v
	@echo "Volumes supprimés. Relancez 'make up' pour repartir à zéro."

# ───────────────────────────────────────────────────────────────────────────────
# Docker Production
# ───────────────────────────────────────────────────────────────────────────────
prod: ## Démarre en production (avec Nginx)
	$(DC) --profile production up -d

prod-down: ## Arrête la production
	$(DC) --profile production down

# ───────────────────────────────────────────────────────────────────────────────
# Docker Dev (hot-reload)
# ───────────────────────────────────────────────────────────────────────────────
up-dev: ## Démarre en mode dev (hot-reload)
	$(DC_DEV) up -d

down-dev: ## Arrête le mode dev
	$(DC_DEV) down
