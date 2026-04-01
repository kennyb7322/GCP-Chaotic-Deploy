# 🔥 GCP Chaotic Deploy — Enterprise Landing Zone

> **Shift-Left · Chaos-First · HIPAA-Compliant**
>
> A fully automated GCP Enterprise Landing Zone deployment framework built on the **Chaotic Deploy™** methodology — where chaos engineering is a first-class deliverable, not an afterthought.

[![CI/CD Pipeline](https://github.com/ucs-solutions/gcp-chaotic-deploy/actions/workflows/deploy.yml/badge.svg)](https://github.com/ucs-solutions/gcp-chaotic-deploy/actions)
[![Terraform](https://img.shields.io/badge/Terraform-1.9+-623CE4?logo=terraform)](https://www.terraform.io/)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://golang.org/)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python)](https://python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![HIPAA](https://img.shields.io/badge/HIPAA-Compliant-00C853)](#hipaa-controls-map)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [The Chaotic Deploy Methodology](#the-chaotic-deploy-methodology)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Deployment Guide](#deployment-guide)
  - [Stage 1: Foundation](#stage-1-foundation)
  - [Stage 2: Identity & Network](#stage-2-identity--network)
  - [Stage 3: Security](#stage-3-security)
  - [Stage 4: Workloads & Observability](#stage-4-workloads--observability)
- [Terraform Modules (15)](#terraform-modules-15)
- [Go CLI Tools (3)](#go-cli-tools-3)
- [Python Automation Scripts](#python-automation-scripts)
- [Chaos Engineering Framework](#chaos-engineering-framework)
- [CI/CD Pipeline](#cicd-pipeline)
- [HIPAA Controls Map (16)](#hipaa-controls-map-16)
- [Architecture Decision Records (15)](#architecture-decision-records-15)
- [OPA Policy Gate](#opa-policy-gate)
- [FinOps & Cost Governance](#finops--cost-governance)
- [Runbooks](#runbooks)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This repository implements a **complete GCP Enterprise Landing Zone** for a HIPAA-regulated healthcare organization. The framework goes beyond traditional IaC by embedding chaos engineering, continuous compliance validation, and automated cost governance into the deployment lifecycle from Day 1.

### Key Differentiators

| Feature | Traditional Approach | Chaotic Deploy |
|---|---|---|
| **Chaos Engineering** | Week 8+ (if ever) | Week 1 — Game Day 1 |
| **HIPAA Compliance** | Manual audit at end | Automated, continuous, in CI/CD |
| **Deployment** | Manual `terraform apply` | Go orchestrator with preflight + rollback |
| **Cost Governance** | Monthly review | Real-time FinOps with CUD optimizer |
| **Policy Enforcement** | Documentation | OPA Conftest gate in pipeline |
| **Identity** | Local GCP accounts | Zero-Trust: Entra ID federation only |

### Technology Stack

- **Infrastructure as Code:** Terraform 1.9+ with Terragrunt, 15 composable modules
- **Deployment Orchestration:** Go CLI tools (deploy, chaos, validate)
- **Compliance Automation:** Python scanners (discovery, HIPAA, FinOps)
- **CI/CD:** GitHub Actions with Workload Identity Federation (no SA keys)
- **Policy Gate:** OPA Conftest with 8 HIPAA-aligned policies
- **Chaos Engineering:** 8 experiments with SLO-based auto-abort
- **Security Scanning:** tfsec, Checkov, SARIF integration

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    GCP ORGANIZATION                              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Assured Workloads (HIPAA)                                  │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │ │
│  │  │   Prod   │ │ NonProd  │ │ Sandbox  │ │    Shared     │  │ │
│  │  │  Folder  │ │  Folder  │ │  Folder  │ │   Services    │  │ │
│  │  │          │ │          │ │          │ │               │  │ │
│  │  │ ┌──────┐ │ │ ┌──────┐ │ │ ┌──────┐ │ │ ┌───────────┐ │  │ │
│  │  │ │ GKE  │ │ │ │ GKE  │ │ │ │ Dev  │ │ │ │ Shared VPC│ │  │ │
│  │  │ │ Auto │ │ │ │ Auto │ │ │ │ Labs │ │ │ │  Host     │ │  │ │
│  │  │ └──────┘ │ │ └──────┘ │ │ └──────┘ │ │ └───────────┘ │  │ │
│  │  │ ┌──────┐ │ │ ┌──────┐ │ │          │ │ ┌───────────┐ │  │ │
│  │  │ │Cloud │ │ │ │Cloud │ │ │          │ │ │  Cloud    │ │  │ │
│  │  │ │ SQL  │ │ │ │ SQL  │ │ │          │ │ │  KMS      │ │  │ │
│  │  │ └──────┘ │ │ └──────┘ │ │          │ │ └───────────┘ │  │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────┐  ┌────────────────────────────────┐  │
│  │  Security Layer         │  │  Observability                 │  │
│  │  • VPC Service Controls │  │  • Cloud Audit Logs → BQ      │  │
│  │  • SCC Premium          │  │  • GCS Immutable Archive      │  │
│  │  • Binary Authorization │  │  • Splunk SIEM Integration    │  │
│  │  • Hierarchical FW      │  │  • Cloud Monitoring + Alerts  │  │
│  └────────────────────────┘  └────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Network: Hub-Spoke Shared VPC                              │  │
│  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────────────┐   │  │
│  │  │ Prod   │  │NonProd │  │Shared  │  │ Chaos Eng      │   │  │
│  │  │ Subnet │  │ Subnet │  │Svc Sub │  │ Subnet         │   │  │
│  │  │10.10/20│  │10.11/20│  │10.12/22│  │ 10.13.0.0/24   │   │  │
│  │  └────────┘  └────────┘  └────────┘  └────────────────┘   │  │
│  │                    │                                        │  │
│  │              ┌─────┴──────┐                                 │  │
│  │              │  HA VPN    │──── Azure (Entra ID)            │  │
│  │              │  2 Tunnels │                                  │  │
│  │              └────────────┘                                 │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## The Chaotic Deploy Methodology

The Chaotic Deploy™ methodology inverts the traditional cloud migration playbook:

### Three Core Principles

1. **Shift-Left Everything** — Compliance, security, and cost controls are implemented in Week 1-2, not Week 8. Every Terraform module ships with OPA policies, Terratest, and cost estimation baked in.

2. **Chaos From Day 1** — Chaos experiments begin in Week 1 on non-prod. Every architecture assumption is tested before workloads migrate. Bi-weekly game days surface failure modes before they become incidents.

3. **Zero-Trust Identity** — No local GCP accounts. All access via Entra ID SAML federation from Day 1. Workload Identity Federation replaces SA key files. Break-glass requires dual approval and is logged to SIEM.

### 8-Week Delivery Timeline

```
Week 1-2:  Discovery + Identity Federation + First Chaos Game Day
Week 3-4:  Architecture Design + Org Policies + Network + CMEK
Week 5-6:  Security Stack + GKE + CI/CD Pipeline + Game Day 2-3
Week 7-8:  Production Cutover + Runbooks + Hypercare + Game Day 4
```

---

## Repository Structure

```
gcp-chaotic-deploy/
├── cmd/                           # Go CLI tools
│   ├── deploy/main.go             # Stage-by-stage Terraform orchestrator
│   ├── chaos/main.go              # Chaos game day orchestrator
│   └── validate/main.go           # Pre-deploy readiness validator
│
├── terraform/
│   ├── modules/                   # 15 composable Terraform modules
│   │   ├── landing-zone-root/     # Org bootstrap, billing, audit, Assured Workloads
│   │   ├── org-policies/          # 10 org policy constraints
│   │   ├── folder-structure/      # Environment folder hierarchy
│   │   ├── cloud-identity/        # 7 Cloud Identity groups, SAML, SCIM
│   │   ├── shared-vpc/            # Hub-spoke VPC, subnets, NAT, PSA
│   │   ├── ha-vpn/                # HA VPN to Azure with BGP
│   │   ├── hierarchical-firewall/ # Org + folder firewall policies
│   │   ├── cloud-kms-cmek/        # KMS keyrings, HSM for prod, rotation
│   │   ├── vpc-service-controls/  # VPC SC perimeter for PHI
│   │   ├── scc/                   # SCC Premium + Splunk integration
│   │   ├── binary-authorization/  # Binary Auth + SLSA L3 attestors
│   │   ├── audit-logging/         # BQ sink + GCS archive (7-year)
│   │   ├── budget-alerts/         # Budget alerts at 50/80/100%
│   │   ├── gke-cluster/           # GKE Autopilot, WIF, Binary Auth
│   │   └── workload-identity/     # WIF pools for GitHub + Cloud Build
│   │
│   ├── environments/              # Per-environment Terragrunt configs
│   │   ├── prod/
│   │   ├── nonprod/
│   │   ├── sandbox/
│   │   └── shared/
│   │
│   ├── policies/                  # OPA Conftest policies (8 rules)
│   │   └── hipaa.rego
│   └── terragrunt.hcl             # Root Terragrunt configuration
│
├── scripts/
│   └── python/
│       ├── discovery/scanner.py   # GCP org discovery & inventory
│       ├── compliance/            # HIPAA continuous compliance validator
│       │   └── hipaa_validator.py # 16 HIPAA control checks
│       └── finops/                # FinOps cost analyzer + CUD optimizer
│           └── cost_analyzer.py
│
├── docs/
│   ├── adr/                       # 15 Architecture Decision Records
│   ├── runbooks/                  # Operational runbooks
│   └── diagrams/                  # Architecture diagrams
│
├── .github/
│   └── workflows/
│       └── deploy.yml             # 6-stage CI/CD pipeline
│
├── go.mod                         # Go module definition
├── Makefile                       # Build, test, deploy targets
└── README.md                     # This file
```

---

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|---|---|---|
| Terraform | ≥ 1.9.0 | Infrastructure as Code (ADR-002) |
| Terragrunt | ≥ 0.60 | DRY Terraform configuration |
| Go | ≥ 1.22 | CLI tools (deploy, chaos, validate) |
| Python | ≥ 3.12 | Automation scripts |
| gcloud CLI | Latest | GCP authentication & commands |
| tfsec | Latest | Terraform security scanning |
| Conftest | ≥ 0.50 | OPA policy testing |
| Infracost | Latest | Cost estimation |

### Required GCP Permissions

The deployer service account needs:
- `roles/resourcemanager.organizationAdmin`
- `roles/billing.admin`
- `roles/iam.organizationRoleAdmin`
- `roles/orgpolicy.policyAdmin`
- `roles/compute.xpnAdmin`
- `roles/logging.admin`
- `roles/assuredworkloads.admin`

### Required Secrets (GitHub Actions)

```
GCP_PROJECT            # Admin project ID
GCP_ORG_ID             # Organization ID
GCP_BILLING_ACCOUNT    # Billing Account ID
WIF_PROVIDER           # Workload Identity Federation provider
WIF_SA                 # Service account for WIF
INFRACOST_API_KEY      # Infracost API key
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/ucs-solutions/gcp-chaotic-deploy.git
cd gcp-chaotic-deploy

# 2. Install dependencies
make setup

# 3. Build Go CLI tools
make build

# 4. Authenticate to GCP
gcloud auth application-default login
gcloud config set project YOUR_PROJECT

# 5. Run discovery scan
python -m scripts.python.discovery.scanner \
  --org-id YOUR_ORG_ID --output both --deep

# 6. Validate environment readiness
./bin/validate --env nonprod --full --json

# 7. Deploy (dry-run first!)
./bin/deploy --stage all --env nonprod --dry-run

# 8. Deploy for real
./bin/deploy --stage 1 --env nonprod --approve

# 9. Run first chaos game day
./bin/chaos --experiment CE-001 --env nonprod

# 10. Check HIPAA compliance
python -m scripts.python.compliance.hipaa_validator \
  --org-id YOUR_ORG_ID --output table
```

---

## Deployment Guide

### Stage 1: Foundation

Deploys the organizational bootstrap: billing export, audit logging sink, Assured Workloads HIPAA package, and folder structure.

```bash
# Dry-run
./bin/deploy --stage 1 --env nonprod --dry-run

# Apply
./bin/deploy --stage 1 --env nonprod --approve

# Modules deployed:
#   landing-zone-root  → Org resources, billing export, Assured Workloads
#   org-policies       → 10 org policy constraints
#   folder-structure   → Prod/NonProd/Sandbox/Shared/Security folders
```

**Validation checkpoint:**
```bash
./bin/validate --env nonprod --check terraform,org-policy
```

### Stage 2: Identity & Network

Deploys Cloud Identity groups with Entra ID SAML federation, Shared VPC hub-spoke topology, HA VPN to Azure, and hierarchical firewall policies.

```bash
./bin/deploy --stage 2 --env nonprod --approve

# Modules deployed:
#   cloud-identity        → 7 groups, SAML federation, SCIM, break-glass SA
#   shared-vpc            → Hub-spoke VPC, 4 subnets, NAT, PSA
#   ha-vpn                → 2 HA VPN tunnels to Azure with BGP
#   hierarchical-firewall → Org + folder deny-all + allow rules
```

**Post-deploy chaos experiment:**
```bash
./bin/chaos --experiment CE-002 --env nonprod  # HA VPN Failover Drill
```

### Stage 3: Security

Deploys the four-layer security stack: CMEK encryption, VPC Service Controls, SCC Premium, and Binary Authorization.

```bash
./bin/deploy --stage 3 --env nonprod --approve

# Modules deployed:
#   cloud-kms-cmek        → Keyrings + keys per env (HSM for prod)
#   vpc-service-controls  → PHI perimeter, access levels, dry-run
#   scc                   → SCC Premium, Pub/Sub → Splunk
#   binary-authorization  → Binary Auth policy, 2 attestors
```

**Post-deploy chaos experiments:**
```bash
./bin/chaos --experiment CE-003 --env nonprod  # CMEK Key Rotation
./bin/chaos --experiment CE-005 --env nonprod  # VPC SC Block Test
```

### Stage 4: Workloads & Observability

Deploys GKE Autopilot cluster, Workload Identity Federation, centralized audit logging, and budget alerts.

```bash
./bin/deploy --stage 4 --env nonprod --approve

# Modules deployed:
#   audit-logging     → BQ org sink + GCS immutable archive (7yr)
#   budget-alerts     → Alerts at 50/80/100% via Pub/Sub
#   gke-cluster       → GKE Autopilot, private, WIF, Binary Auth
#   workload-identity → WIF pools for GitHub Actions + Cloud Build
```

**Full game day:**
```bash
./bin/chaos --gameday --env nonprod
```

---

## Terraform Modules (15)

| # | Module | Purpose | ADR | Terratest |
|---|---|---|---|---|
| 1 | `landing-zone-root` | Org bootstrap, billing, Assured Workloads | ADR-001, ADR-011 | ✓ |
| 2 | `org-policies` | 10 organization policy constraints | ADR-001, ADR-015 | ✓ |
| 3 | `folder-structure` | Environment folder hierarchy | ADR-001 | ✓ |
| 4 | `cloud-identity` | Cloud Identity groups, SAML, SCIM | ADR-004 | ✓ |
| 5 | `shared-vpc` | Hub-spoke VPC, subnets, NAT, PSA | ADR-003 | ✓ |
| 6 | `ha-vpn` | HA VPN to Azure with BGP | ADR-003 | ✓ |
| 7 | `hierarchical-firewall` | Org + folder firewall policies | ADR-014 | ✓ |
| 8 | `cloud-kms-cmek` | KMS keyrings, HSM for prod, 365d rotation | ADR-005 | ✓ |
| 9 | `vpc-service-controls` | VPC SC perimeter for PHI projects | ADR-006 | ✓ |
| 10 | `scc` | SCC Premium + Splunk Pub/Sub notifications | ADR-013 | ✓ |
| 11 | `binary-authorization` | Binary Auth + SLSA L3 attestors | ADR-010 | ✓ |
| 12 | `audit-logging` | BQ org sink + GCS archive (7-year HIPAA) | ADR-008 | ✓ |
| 13 | `budget-alerts` | Budget alerts at 50/80/100% | ADR-012 | — |
| 14 | `gke-cluster` | GKE Autopilot, private, WIF, Binary Auth | ADR-010 | ✓ |
| 15 | `workload-identity` | WIF pools for GitHub + Cloud Build | ADR-015 | ✓ |

All modules feature: CMEK encryption, WIF (no SA keys), OPA Conftest policy gate, Infracost estimation, and SLSA L3 provenance via Cloud Build.

---

## Go CLI Tools (3)

### `cmd/deploy` — Terraform Orchestrator

Stage-by-stage deployment with preflight checks, dry-run mode, and automatic rollback on failure.

```bash
# Deploy specific stage
./bin/deploy --stage 2 --env nonprod --approve

# Dry-run all stages
./bin/deploy --stage all --env prod --dry-run

# JSON output for CI
./bin/deploy --stage 1 --env nonprod --approve --json
```

### `cmd/chaos` — Chaos Orchestrator

8 chaos experiments with SLO-based auto-abort, blast-radius containment, and automatic rollback.

```bash
# Single experiment
./bin/chaos --experiment CE-001 --env nonprod

# Full game day (all 8 experiments)
./bin/chaos --gameday --env nonprod

# Production (requires executive approval flag)
./bin/chaos --experiment CE-007 --env prod --prod-approval
```

### `cmd/validate` — Pre-Deploy Validator

15 validation checks across auth, IAM, Terraform state, org policies, network, security, compliance, and identity.

```bash
# Critical checks only
./bin/validate --env prod

# Full validation suite
./bin/validate --env prod --full --json

# CI gate mode (exit 1 on critical failure)
./bin/validate --env prod --full --ci
```

---

## Python Automation Scripts

### Discovery Scanner

```bash
python -m scripts.python.discovery.scanner \
  --org-id 123456789 \
  --output both \
  --deep \
  --file discovery-report
```

Generates a comprehensive inventory: projects, APIs, IAM bindings, networks, org policies, compliance gaps, and actionable recommendations. Exports as JSON and XLSX.

### HIPAA Compliance Validator

```bash
# One-time check
python -m scripts.python.compliance.hipaa_validator \
  --org-id 123456789 --output table

# Continuous monitoring (every hour)
python -m scripts.python.compliance.hipaa_validator \
  --org-id 123456789 --continuous --interval 3600
```

Validates 16 HIPAA security controls mapped to GCP configurations. Generates compliance scores and identifies critical findings.

### FinOps Cost Analyzer

```bash
python -m scripts.python.finops.cost_analyzer \
  --project billing-export \
  --dataset billing \
  --days 30 \
  --budget 50000
```

Analyzes billing data, identifies CUD opportunities, generates budget utilization reports, and forecasts month-end spend.

---

## Chaos Engineering Framework

### 8 Experiments

| ID | Experiment | Blast Radius | SLO Target |
|---|---|---|---|
| CE-001 | Zone Failure Simulation | nonprod-zone-a | Uptime > 99.9% |
| CE-002 | HA VPN Failover Drill | vpn-tunnel-0 | Tunnel uptime > 99% |
| CE-003 | CMEK Key Rotation Chaos | kms-keyring-nonprod | Decrypt p99 < 200ms |
| CE-004 | GKE Node Pool Drain | gke-nodepool-general | Pod ready > 95% |
| CE-005 | VPC SC Perimeter Block Test | vpc-sc-perimeter-phi | SC violations = 0 |
| CE-006 | IAM Permission Revocation | iam-binding-viewer | SCC detection < 15m |
| CE-007 | Cloud SQL Failover | cloudsql-nonprod | RTO < 60s |
| CE-008 | Pub/Sub Message Storm | pubsub-nonprod | Ack p99 < 500ms |

### Safety Controls

- **SLO-Based Auto-Abort:** Every experiment monitors a steady-state hypothesis. If the SLO breaches the threshold, the experiment auto-aborts and executes rollback commands.
- **Blast Radius Containment:** Each experiment declares its blast radius. No experiment can affect resources outside its declared scope.
- **Executive Approval Gate:** Production chaos requires the `--prod-approval` flag, which maps to a signed approval from the executive sponsor.
- **Graceful Shutdown:** SIGINT/SIGTERM triggers emergency rollback of all in-progress experiments.

### Game Day Cadence

- **Week 1:** CE-001 (Zone Failure) — validate multi-zone redundancy
- **Week 3:** CE-002, CE-003 (VPN + CMEK) — validate network + encryption resilience
- **Week 5:** CE-004, CE-005, CE-006 (GKE + VPC SC + IAM) — validate workload + security
- **Week 7:** CE-007, CE-008 (SQL + Pub/Sub) — validate data layer resilience

Target chaos score: **85/100**

---

## CI/CD Pipeline

The GitHub Actions pipeline runs 6 stages:

```
┌──────────┐   ┌──────────┐   ┌──────────┐
│  1. Lint  │──▶│ 2. OPA   │──▶│ 3. Cost  │
│  tfsec    │   │ Conftest │   │ Infracost│
│  Checkov  │   │ 8 Rules  │   │ PR Comment│
│  Go/Py    │   │          │   │          │
└──────────┘   └──────────┘   └──────────┘
                    │
                    ▼
┌──────────┐   ┌──────────┐   ┌──────────┐
│4.Terratest│──▶│ 5.Deploy │──▶│ 6. HIPAA │
│ Go tests  │   │ Go Orch  │   │ Validator│
│ 12 modules│   │ Rollback │   │ 16 Ctrls │
│           │   │ Auto-Appr│   │ Gate >80%│
└──────────┘   └──────────┘   └──────────┘
```

Key features:
- **Workload Identity Federation** — no SA key files (ADR-015)
- **Concurrency control** — one deploy per environment at a time
- **SARIF upload** — Checkov findings appear in GitHub Security tab
- **HIPAA gate** — deployment fails if compliance score drops below 80%

---

## HIPAA Controls Map (16)

| Control | HIPAA Section | GCP Implementation |
|---|---|---|
| HIPAA-001 | §164.312(a)(2)(i) | Cloud Identity + Entra ID SAML |
| HIPAA-002 | §164.312(a)(2)(ii) | Break-glass SA in Secret Manager |
| HIPAA-003 | §164.312(a)(2)(iii) | Entra ID session policies |
| HIPAA-004 | §164.312(a)(2)(iv) | CMEK via Cloud KMS (HSM prod) |
| HIPAA-005 | §164.312(b) | Audit Logs → BQ (7-year retention) |
| HIPAA-006 | §164.312(c)(1) | GCS versioning + retention locks |
| HIPAA-007 | §164.312(e)(1) | TLS 1.3 + HA VPN IKEv2 |
| HIPAA-008 | §164.312(d) | Entra ID MFA + no SA keys |
| HIPAA-009 | §164.310(c) | Shielded VMs (org policy) |
| HIPAA-010 | §164.310(a)(1) | Assured Workloads (US-only) |
| HIPAA-011 | §164.308(a)(7)(ii)(A) | Cloud SQL backups + GCS replication |
| HIPAA-012 | §164.308(a)(7)(ii)(B) | Multi-zone + chaos validation |
| HIPAA-013 | §164.308(a)(6) | SCC Premium → Splunk SIEM |
| HIPAA-014 | §164.308(a)(1)(ii)(A) | SCC vulnerability scanner |
| HIPAA-015 | §164.308(b)(1) | Google Cloud BAA via Assured Workloads |
| HIPAA-016 | §164.308(a)(3)(ii)(C) | Entra ID lifecycle + SCIM |

---

## Architecture Decision Records (15)

| ADR | Title | Status |
|---|---|---|
| ADR-001 | GCP as Primary Cloud for PHI Workloads | Accepted |
| ADR-002 | Terraform 1.9 + Terragrunt for IaC | Accepted |
| ADR-003 | Shared VPC Hub-Spoke Network Topology | Accepted |
| ADR-004 | Cloud Identity + Entra ID SAML 2.0 | Accepted |
| ADR-005 | CMEK for All PHI Workloads | Accepted |
| ADR-006 | VPC Service Controls Perimeter | Accepted |
| ADR-007 | GitOps via Cloud Build + ArgoCD | Accepted |
| ADR-008 | BigQuery as Central Audit Log Sink | Accepted |
| ADR-009 | Chaos Engineering as First-Class Deliverable | Accepted |
| ADR-010 | Binary Authorization for GKE | Accepted |
| ADR-011 | Assured Workloads HIPAA Package | Accepted |
| ADR-012 | FinOps Weekly Cadence | Accepted |
| ADR-013 | SCC Premium as SIEM Data Source | Accepted |
| ADR-014 | Hierarchical Firewall Policies | Accepted |
| ADR-015 | Workload Identity Federation for CI/CD | Accepted |

---

## OPA Policy Gate

8 Conftest policies enforce HIPAA guardrails in the CI/CD pipeline:

| Policy | Rule | Severity |
|---|---|---|
| P-001 | No public GCS buckets | DENY |
| P-002 | CMEK required for PHI resources | DENY |
| P-003 | No external IPs on VMs | DENY |
| P-004 | VPC flow logs required | WARN |
| P-005 | Labels required on all resources | DENY |
| P-006 | KMS keys must have rotation | DENY |
| P-007 | No SA key creation | DENY |
| P-008 | US region only | DENY |

---

## FinOps & Cost Governance

- **Budget alerts** at 50%, 80%, and 100% via Pub/Sub + Cloud Monitoring
- **CUD optimizer** identifies Committed Use Discount opportunities
- **Infracost** runs on every PR with cost diff comments
- **Label enforcement** via org policy — every resource tagged for cost allocation
- **Weekly cadence** — automated cost report generated every Monday (ADR-012)

---

## Runbooks

| Runbook | Trigger |
|---|---|
| `break-glass-access.md` | Emergency admin access needed |
| `vpn-failover.md` | HA VPN tunnel failure |
| `cmek-rotation.md` | KMS key rotation procedure |
| `scc-finding-response.md` | SCC Premium critical finding |
| `incident-response.md` | Security incident detected |
| `gke-node-failure.md` | GKE node pool failure |
| `compliance-audit.md` | HIPAA audit preparation |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Ensure all checks pass: `make lint test`
4. Submit a PR — the CI pipeline will run lint, OPA, Infracost, and Terratest

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

**Built by [UCS Solutions](https://ucssolutions.com)** — 30+ years of enterprise architecture, cloud migration, and security consulting across 400+ client engagements.

*Kenneth P. Barnes, Ph.D. — Founder & CTO/CISO*
