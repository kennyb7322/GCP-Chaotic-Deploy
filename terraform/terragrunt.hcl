# ──────────────────────────────────────────────────────────────
# Terragrunt Root Configuration
# DRY config for all environments. Module-specific overrides
# in environments/{env}/{module}/terragrunt.hcl
# ──────────────────────────────────────────────────────────────

locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  environment = local.env_vars.locals.environment
  org_id      = local.env_vars.locals.org_id
  region      = local.env_vars.locals.region
}

remote_state {
  backend = "gcs"
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    project  = "${local.environment}-terraform-admin"
    location = local.region
    bucket   = "${local.environment}-terraform-state"
    prefix   = "${path_relative_to_include()}/terraform.tfstate"
  }
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
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
}

provider "google" {
  project = "${local.environment}-host"
  region  = "${local.region}"
}

provider "google-beta" {
  project = "${local.environment}-host"
  region  = "${local.region}"
}
EOF
}

inputs = {
  org_id      = local.org_id
  region      = local.region
  environment = local.environment
  labels = {
    managed_by  = "terraform"
    environment = local.environment
    compliance  = "hipaa"
    project     = "chaotic-deploy"
  }
}
