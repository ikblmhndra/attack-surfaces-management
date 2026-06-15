# ============================================================
# ASM Platform — Makefile
# ============================================================
.PHONY: help setup up down build rebuild logs ps health \
        migrate migrate-create migrate-rollback \
        shell-api shell-db shell-worker \
        test test-unit test-integration lint format \
        clean clean-all backup restore \
        nuclei-update scan-org generate-ssl \
        workers-up workers-scale prod-deploy \
        changelog

SHELL := /bin/bash
DOCKER := docker
COMPOSE := docker compose
ENV_FILE := .env
COMPOSE_FILE := docker-compose.yml

# Colors
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[0;33m
BLUE   := \033[0;34m
CYAN   := \033[0;36m
NC     := \033[0m

# ── Default target ────────────────────────────────────────────
help: ## Show this help message
	@echo ""
	@echo "  $(CYAN)ASM Platform$(NC) — Attack Surface Management"
	@echo ""
	@echo "  $(YELLOW)Setup & Running$(NC)"
	@awk 'BEGIN {FS = ":.*##"; section=""} /^## / {section=$$2} /^[a-zA-Z_-]+:.*##/ {printf "  $(GREEN)%-22s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

# ── Setup ─────────────────────────────────────────────────────
## Setup & Running
setup: ## Initial platform setup (copy env, generate SSL, pull images)
	@echo "$(CYAN)Setting up ASM Platform...$(NC)"
	@if [ ! -f $(ENV_FILE) ]; then \
		cp .env.example $(ENV_FILE); \
		echo "$(YELLOW)Created .env — edit it before starting!$(NC)"; \
	fi
	@$(MAKE) generate-ssl
	@$(MAKE) nuclei-update
	@$(COMPOSE) pull
	@echo "$(GREEN)Setup complete! Edit .env then run: make up$(NC)"

generate-ssl: ## Generate self-signed SSL certificate for development
	@echo "$(CYAN)Generating SSL certificate...$(NC)"
	@mkdir -p infrastructure/nginx/ssl
	@if [ ! -f infrastructure/nginx/ssl/cert.pem ]; then \
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
			-keyout infrastructure/nginx/ssl/key.pem \
			-out infrastructure/nginx/ssl/cert.pem \
			-subj "/C=US/ST=State/L=City/O=ASM Platform/CN=localhost" 2>/dev/null; \
		echo "$(GREEN)SSL certificate generated$(NC)"; \
	else \
		echo "$(YELLOW)SSL certificate already exists$(NC)"; \
	fi

# ── Start/Stop ─────────────────────────────────────────────────
up: ## Start all services
	@echo "$(CYAN)Starting ASM Platform...$(NC)"
	@$(COMPOSE) up -d
	@echo "$(GREEN)Platform started! Waiting for health checks...$(NC)"
	@sleep 5
	@$(MAKE) health

up-build: ## Build and start all services
	@$(COMPOSE) up -d --build

up-infra: ## Start infrastructure only (DB, Redis, RabbitMQ, MinIO)
	@$(COMPOSE) up -d postgres redis rabbitmq minio opensearch
	@echo "$(GREEN)Infrastructure started$(NC)"

down: ## Stop all services
	@$(COMPOSE) down

down-volumes: ## Stop all services and remove volumes (DESTRUCTIVE)
	@echo "$(RED)WARNING: This will delete all data!$(NC)"
	@read -p "Are you sure? (yes/no): " confirm && [ "$$confirm" = "yes" ] || exit 1
	@$(COMPOSE) down -v

restart: ## Restart all services
	@$(COMPOSE) restart

restart-api: ## Restart API service only
	@$(COMPOSE) restart api

restart-workers: ## Restart all worker services
	@$(COMPOSE) restart worker-discovery worker-port worker-crawl worker-nuclei \
		worker-scanner worker-screenshot worker-enrichment worker-correlation worker-risk \
		worker-notification scheduler

# ── Build ─────────────────────────────────────────────────────
build: ## Build all Docker images
	@echo "$(CYAN)Building images...$(NC)"
	@$(COMPOSE) build --parallel

build-api: ## Build API image only
	@$(COMPOSE) build api

build-frontend: ## Build frontend image only
	@$(COMPOSE) build frontend

build-workers: ## Build workers image only
	@$(COMPOSE) build worker-discovery worker-port worker-crawl worker-nuclei \
		worker-scanner worker-screenshot worker-enrichment

rebuild: ## Force rebuild all images (no cache)
	@$(COMPOSE) build --no-cache --parallel

# ── Database ──────────────────────────────────────────────────
migrate: ## Run database migrations
	@echo "$(CYAN)Running migrations...$(NC)"
	@$(COMPOSE) exec api alembic upgrade head
	@echo "$(GREEN)Migrations complete$(NC)"

migrate-create: ## Create a new migration (usage: make migrate-create MSG="add xyz table")
	@$(COMPOSE) exec api alembic revision --autogenerate -m "$(MSG)"

migrate-rollback: ## Roll back the last migration
	@$(COMPOSE) exec api alembic downgrade -1

migrate-history: ## Show migration history
	@$(COMPOSE) exec api alembic history --verbose

db-shell: ## Open PostgreSQL shell
	@$(COMPOSE) exec postgres psql -U $$(grep POSTGRES_USER .env | cut -d= -f2) \
		-d $$(grep POSTGRES_DB .env | cut -d= -f2)

db-dump: ## Backup the database
	@echo "$(CYAN)Creating database backup...$(NC)"
	@mkdir -p backups
	@$(COMPOSE) exec postgres pg_dump \
		-U $$(grep POSTGRES_USER .env | cut -d= -f2) \
		$$(grep POSTGRES_DB .env | cut -d= -f2) \
		> backups/asm-db-$$(date +%Y%m%d-%H%M%S).sql
	@echo "$(GREEN)Backup saved to backups/$(NC)"

db-restore: ## Restore database from backup (usage: make db-restore FILE=backups/xxx.sql)
	@echo "$(YELLOW)Restoring from $(FILE)...$(NC)"
	@cat $(FILE) | $(COMPOSE) exec -T postgres psql \
		-U $$(grep POSTGRES_USER .env | cut -d= -f2) \
		$$(grep POSTGRES_DB .env | cut -d= -f2)
	@echo "$(GREEN)Restore complete$(NC)"

# ── Shell access ──────────────────────────────────────────────
shell-api: ## Open a shell in the API container
	@$(COMPOSE) exec api /bin/bash

shell-worker: ## Open a shell in the discovery worker
	@$(COMPOSE) exec worker-discovery /bin/bash

shell-redis: ## Open Redis CLI
	@$(COMPOSE) exec redis redis-cli -a $$(grep REDIS_PASSWORD .env | cut -d= -f2)

# ── Monitoring ────────────────────────────────────────────────
logs: ## Follow all service logs
	@$(COMPOSE) logs -f --tail=100

logs-api: ## Follow API logs
	@$(COMPOSE) logs -f api --tail=100

logs-workers: ## Follow all worker logs
	@$(COMPOSE) logs -f worker-discovery worker-port worker-crawl worker-nuclei worker-scanner worker-screenshot worker-correlation worker-risk worker-enrichment worker-notification worker-scheduler --tail=50

logs-nginx: ## Follow NGINX logs
	@$(COMPOSE) logs -f nginx --tail=100

ps: ## Show service status
	@$(COMPOSE) ps

health: ## Check health of all services
	@echo "$(CYAN)Checking service health...$(NC)"
	@for service in postgres redis rabbitmq minio opensearch api frontend; do \
		status=$$($(COMPOSE) ps $$service --format json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0].get('Health','unknown'))" 2>/dev/null || echo "unknown"); \
		if [ "$$status" = "healthy" ]; then \
			echo "  $(GREEN)✓$(NC) $$service: $$status"; \
		elif [ "$$status" = "unknown" ] || [ -z "$$status" ]; then \
			echo "  $(YELLOW)?$(NC) $$service: checking..."; \
		else \
			echo "  $(RED)✗$(NC) $$service: $$status"; \
		fi \
	done

metrics: ## Open Prometheus metrics in browser
	@open http://localhost:9090 || xdg-open http://localhost:9090 2>/dev/null || echo "Open: http://localhost:9090"

grafana: ## Open Grafana dashboard in browser
	@open http://localhost:3001 || xdg-open http://localhost:3001 2>/dev/null || echo "Open: http://localhost:3001"

rabbitmq-ui: ## Open RabbitMQ management UI
	@open http://localhost:15672 || xdg-open http://localhost:15672 2>/dev/null || echo "Open: http://localhost:15672"

# ── Testing ───────────────────────────────────────────────────
## Testing & Quality
test: ## Run all tests
	@$(COMPOSE) exec api pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	@$(COMPOSE) exec api pytest tests/unit/ -v --tb=short

test-integration: ## Run integration tests (requires running services)
	@$(COMPOSE) exec api pytest tests/integration/ -v --tb=short -x

test-coverage: ## Run tests with coverage report
	@$(COMPOSE) exec api pytest tests/ --cov=app --cov-report=html --cov-report=term-missing

lint: ## Run linting
	@echo "$(CYAN)Linting backend...$(NC)"
	@$(COMPOSE) exec api ruff check app/ workers/
	@echo "$(CYAN)Linting frontend...$(NC)"
	@$(COMPOSE) exec frontend npm run lint

format: ## Auto-format code
	@$(COMPOSE) exec api ruff format app/ workers/
	@$(COMPOSE) exec api isort app/ workers/
	@$(COMPOSE) exec frontend npm run format

type-check: ## Run type checking
	@$(COMPOSE) exec api mypy app/
	@$(COMPOSE) exec frontend npm run type-check

security-scan: ## Run security scanning (bandit + safety)
	@$(COMPOSE) exec api bandit -r app/ -ll
	@$(COMPOSE) exec api safety check

# ── Scanner tools ──────────────────────────────────────────────
## Scanner Tools
nuclei-update: ## Update nuclei templates
	@echo "$(CYAN)Updating nuclei templates...$(NC)"
	@mkdir -p /tmp/nuclei-templates
	@if command -v nuclei &> /dev/null; then \
		nuclei -update-templates; \
	else \
		echo "$(YELLOW)nuclei not found locally — will update in container$(NC)"; \
		$(COMPOSE) exec -T worker-nuclei nuclei -update-templates 2>/dev/null || true; \
	fi
	@echo "$(GREEN)Templates updated$(NC)"

scan-org: ## Trigger a scan for an org (usage: make scan-org ORG_ID=xxx TOKEN=yyy)
	@curl -s -X POST \
		-H "Authorization: Bearer $(TOKEN)" \
		-H "Content-Type: application/json" \
		-d '{"scan_type": "full", "modules": []}' \
		https://localhost/api/v1/organizations/$(ORG_ID)/scans \
		--insecure | python3 -m json.tool

# ── Scaling ───────────────────────────────────────────────────
## Scaling
workers-scale: ## Scale workers (usage: make workers-scale NUCLEI=4 DISCOVERY=3 PORT=3 CRAWL=2 ENRICHMENT=2)
	@$(COMPOSE) up -d --scale worker-nuclei=$(or $(NUCLEI),2) \
		--scale worker-discovery=$(or $(DISCOVERY),2) \
		--scale worker-port=$(or $(PORT),3) \
		--scale worker-crawl=$(or $(CRAWL),2) \
		--scale worker-scanner=$(or $(SCANNER),2) \
		--scale worker-enrichment=$(or $(ENRICHMENT),2) \
		--no-recreate

# ── Production ────────────────────────────────────────────────
## Production
prod-deploy: ## Production deployment (pull, build, migrate, restart)
	@echo "$(CYAN)Deploying ASM Platform...$(NC)"
	@git pull origin main
	@$(COMPOSE) pull
	@$(COMPOSE) build --parallel
	@$(MAKE) migrate
	@$(COMPOSE) up -d --remove-orphans
	@$(MAKE) health
	@echo "$(GREEN)Deployment complete$(NC)"

prod-backup: ## Full production backup (DB + MinIO)
	@$(MAKE) db-dump
	@echo "$(CYAN)Backing up MinIO...$(NC)"
	@mkdir -p backups/minio
	@$(COMPOSE) exec -T minio mc mirror asm/screenshots backups/minio/ 2>/dev/null || true
	@echo "$(GREEN)Backup complete$(NC)"

# ── Cleanup ───────────────────────────────────────────────────
## Cleanup
clean: ## Clean build artifacts and Python cache
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name node_modules -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .next -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)Cleaned$(NC)"

clean-docker: ## Remove stopped containers and unused images
	@$(DOCKER) system prune -f
	@echo "$(GREEN)Docker cleaned$(NC)"

# ── Changelog ──────────────────────────────────────────────────
changelog: ## Append a changelog entry (interactive)
	@bash scripts/changelog.sh entry

changelog-add: ## Append a changelog entry (CLI: make changelog-add DATE="..." TITLE="..." CATEGORY="..." DESC="..." FILE="..." ISSUE="..." FIX="...")
	@bash scripts/changelog.sh add "$(DATE)" "$(TITLE)" "$(CATEGORY)" "$(DESC)" "$(FILE)" "$(ISSUE)" "$(FIX)"

# ── Info ──────────────────────────────────────────────────────
version: ## Show platform version info
	@echo "ASM Platform v1.0.0"
	@echo "Docker: $$(docker --version)"
	@echo "Compose: $$(docker compose version)"
	@echo "Git: $$(git rev-parse --short HEAD 2>/dev/null || echo 'no git')"
