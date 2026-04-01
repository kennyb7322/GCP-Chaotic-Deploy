# ╔═══════════════════════════════════════════════════════════════╗
# ║  GCP Chaotic Deploy — Project Makefile                       ║
# ║  Shift-Left • Chaos-First • HIPAA-Compliant                 ║
# ╚═══════════════════════════════════════════════════════════════╝

.PHONY: all setup lint test plan deploy chaos validate compliance clean help

ENV         ?= nonprod
STAGE       ?= all
GO          := go
TF          := terraform
PYTHON      := python3

# ── Setup ──────────────────────────────────────────────────────
setup:                    ## Install all dependencies
	@echo "▶ Installing Go dependencies..."
	$(GO) mod download
	@echo "▶ Installing Python dependencies..."
	pip install openpyxl ruff mypy --quiet
	@echo "▶ Installing Terraform tools..."
	@which tfsec > /dev/null || echo "Install tfsec: brew install tfsec"
	@which conftest > /dev/null || echo "Install conftest: brew install conftest"
	@which infracost > /dev/null || echo "Install infracost: brew install infracost"
	@echo "✓ Setup complete"

# ── Build ──────────────────────────────────────────────────────
build:                    ## Build all Go binaries
	$(GO) build -o bin/deploy ./cmd/deploy
	$(GO) build -o bin/chaos ./cmd/chaos
	$(GO) build -o bin/validate ./cmd/validate
	@echo "✓ Binaries in ./bin/"

# ── Lint ───────────────────────────────────────────────────────
lint:                     ## Lint all code (Go, Python, Terraform)
	@echo "▶ Go lint..."
	golangci-lint run ./...
	@echo "▶ Python lint..."
	ruff check scripts/python/
	@echo "▶ Terraform format..."
	$(TF) fmt -check -recursive terraform/
	@echo "▶ tfsec scan..."
	tfsec terraform/modules/
	@echo "✓ All lints passed"

# ── Test ───────────────────────────────────────────────────────
test:                     ## Run all tests
	@echo "▶ Go unit tests..."
	$(GO) test -v -count=1 ./...
	@echo "▶ Terratest integration tests..."
	cd terraform/test && $(GO) test -v -timeout 30m ./...

# ── Terraform ──────────────────────────────────────────────────
plan:                     ## Run terraform plan (dry-run)
	$(GO) run ./cmd/deploy --stage $(STAGE) --env $(ENV) --dry-run

deploy:                   ## Deploy to target environment
	@echo "⚠  Deploying stage $(STAGE) to $(ENV)..."
	$(GO) run ./cmd/deploy --stage $(STAGE) --env $(ENV) --json

# ── Validation ─────────────────────────────────────────────────
validate:                 ## Run pre-deploy validation
	$(GO) run ./cmd/validate --env $(ENV) --full --json

# ── Chaos Engineering ──────────────────────────────────────────
chaos:                    ## Run chaos experiments
	$(GO) run ./cmd/chaos --gameday --env $(ENV) --json

chaos-single:             ## Run a single chaos experiment (EXPERIMENT=CE-001)
	$(GO) run ./cmd/chaos --experiment $(EXPERIMENT) --env $(ENV) --json

# ── Compliance ─────────────────────────────────────────────────
compliance:               ## Run HIPAA compliance check
	$(PYTHON) -m scripts.python.compliance.hipaa_validator --org-id $(ORG_ID) --output table

# ── Discovery ──────────────────────────────────────────────────
discover:                 ## Run GCP discovery scan
	$(PYTHON) -m scripts.python.discovery.scanner --org-id $(ORG_ID) --output both --deep

# ── FinOps ─────────────────────────────────────────────────────
finops:                   ## Run cost analysis
	$(PYTHON) -m scripts.python.finops.cost_analyzer --project $(BILLING_PROJECT) --budget 50000

# ── Clean ──────────────────────────────────────────────────────
clean:                    ## Clean build artifacts
	rm -rf bin/ terraform/**/.terraform terraform/**/tfplan
	@echo "✓ Cleaned"

# ── Help ───────────────────────────────────────────────────────
help:                     ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
