# ──────────────────────────────────────────────────────────────
# Module: landing-zone-root
# Purpose: Bootstrap the GCP organization — billing export,
#          audit sink, Assured Workloads folders, and bootstrap SA.
# ADRs:    ADR-001, ADR-011
# ──────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.30"
    }
  }
  backend "gcs" {
    bucket = var.state_bucket
    prefix = "landing-zone-root"
  }
}

# ── Variables ──────────────────────────────────────────────────
variable "org_id" {
  description = "GCP Organization ID"
  type        = string
}

variable "billing_account" {
  description = "Billing Account ID"
  type        = string
}

variable "state_bucket" {
  description = "GCS bucket for Terraform remote state"
  type        = string
}

variable "region" {
  description = "Primary GCP region"
  type        = string
  default     = "us-central1"
}

variable "assured_workloads_compliance" {
  description = "Assured Workloads compliance regime"
  type        = string
  default     = "HIPAA"
}

variable "labels" {
  description = "Common labels applied to all resources"
  type        = map(string)
  default = {
    managed_by  = "terraform"
    environment = "shared"
    compliance  = "hipaa"
    project     = "chaotic-deploy"
  }
}

# ── Locals ─────────────────────────────────────────────────────
locals {
  project_prefix = "gcp-lz"
  audit_project  = "${local.project_prefix}-audit-${random_id.suffix.hex}"
  billing_project = "${local.project_prefix}-billing-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 2
}

# ── Bootstrap Project (Audit) ──────────────────────────────────
resource "google_project" "audit" {
  name                = "Landing Zone Audit"
  project_id          = local.audit_project
  org_id              = var.org_id
  billing_account     = var.billing_account
  auto_create_network = false
  labels              = var.labels
}

resource "google_project_service" "audit_apis" {
  for_each = toset([
    "logging.googleapis.com",
    "bigquery.googleapis.com",
    "storage.googleapis.com",
    "cloudkms.googleapis.com",
    "securitycenter.googleapis.com",
    "cloudasset.googleapis.com",
  ])
  project = google_project.audit.project_id
  service = each.value
}

# ── BigQuery Audit Sink (7-year HIPAA retention) ───────────────
resource "google_bigquery_dataset" "audit_logs" {
  project       = google_project.audit.project_id
  dataset_id    = "org_audit_logs"
  friendly_name = "Organization Audit Logs"
  description   = "Aggregated audit logs — 7-year HIPAA retention"
  location      = var.region

  default_table_expiration_ms     = null # No expiration for HIPAA
  default_partition_expiration_ms = null

  labels = var.labels

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }
  access {
    role          = "READER"
    group_by_email = "gcp-compliance@${data.google_organization.org.domain}"
  }
}

resource "google_logging_organization_sink" "audit_bq" {
  name             = "org-audit-bq-sink"
  org_id           = var.org_id
  destination      = "bigquery.googleapis.com/projects/${google_project.audit.project_id}/datasets/${google_bigquery_dataset.audit_logs.dataset_id}"
  include_children = true

  filter = <<-EOT
    logName:"logs/cloudaudit.googleapis.com%2Factivity" OR
    logName:"logs/cloudaudit.googleapis.com%2Fdata_access" OR
    logName:"logs/cloudaudit.googleapis.com%2Fsystem_event"
  EOT

  bigquery_options {
    use_partitioned_tables = true
  }
}

# Grant the sink's writer identity access to the dataset
resource "google_bigquery_dataset_iam_member" "sink_writer" {
  project    = google_project.audit.project_id
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_organization_sink.audit_bq.writer_identity
}

# ── GCS Immutable Archive ──────────────────────────────────────
resource "google_storage_bucket" "audit_archive" {
  name          = "${local.project_prefix}-audit-archive-${random_id.suffix.hex}"
  project       = google_project.audit.project_id
  location      = var.region
  storage_class = "COLDLINE"
  labels        = var.labels

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  retention_policy {
    is_locked        = true
    retention_period = 220752000 # 7 years in seconds
  }

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 365
    }
  }
}

# ── Assured Workloads ─────────────────────────────────────────
resource "google_assured_workloads_workload" "hipaa" {
  provider          = google-beta
  organization      = var.org_id
  location          = var.region
  display_name      = "HIPAA Landing Zone"
  compliance_regime = var.assured_workloads_compliance
  billing_account   = "billingAccounts/${var.billing_account}"

  resource_settings {
    resource_type = "CONSUMER_FOLDER"
    display_name  = "Assured-HIPAA"
  }

  labels = var.labels
}

# ── Data Sources ───────────────────────────────────────────────
data "google_organization" "org" {
  org_id = var.org_id
}

# ── Outputs ────────────────────────────────────────────────────
output "audit_project_id" {
  value       = google_project.audit.project_id
  description = "Project ID for centralized audit logging"
}

output "audit_dataset_id" {
  value       = google_bigquery_dataset.audit_logs.dataset_id
  description = "BigQuery dataset for org audit logs"
}

output "audit_archive_bucket" {
  value       = google_storage_bucket.audit_archive.name
  description = "GCS bucket for immutable audit log archive"
}

output "assured_workload_id" {
  value       = google_assured_workloads_workload.hipaa.id
  description = "Assured Workloads HIPAA resource ID"
}

output "org_domain" {
  value       = data.google_organization.org.domain
  description = "Organization domain"
}
