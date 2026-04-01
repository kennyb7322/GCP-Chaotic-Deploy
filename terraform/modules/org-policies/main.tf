# ──────────────────────────────────────────────────────────────
# Module: org-policies
# Purpose: 10 organization policy constraints enforcing the
#          security baseline across all GCP projects.
# ADRs:    ADR-001, ADR-014, ADR-015
# ──────────────────────────────────────────────────────────────

variable "org_id" {
  type = string
}

# ── Boolean Constraints ────────────────────────────────────────
locals {
  boolean_policies = {
    "compute.requireShieldedVm"              = { enforce = true, desc = "All VMs must use Shielded VM" }
    "compute.vmExternalIpAccess"             = { enforce = true, desc = "No VM external IPs — IAP/VPN only" }
    "iam.disableServiceAccountKeyCreation"   = { enforce = true, desc = "No SA key files — WIF only (ADR-015)" }
    "iam.disableServiceAccountKeyUpload"     = { enforce = true, desc = "No uploading existing SA key files" }
    "storage.publicAccessPrevention"         = { enforce = true, desc = "All GCS buckets block public access" }
    "storage.uniformBucketLevelAccess"       = { enforce = true, desc = "Uniform access on GCS — no ACLs" }
    "compute.skipDefaultNetworkCreation"     = { enforce = true, desc = "No default VPC in new projects" }
    "compute.requireOsLogin"                = { enforce = true, desc = "OS Login for all SSH access" }
  }

  list_policies = {
    "gcp.resourceLocations" = {
      allowed = ["in:us-locations"]
      desc    = "US regions only — HIPAA/Assured Workloads"
    }
    "iam.allowedPolicyMemberDomains" = {
      allowed = [var.org_id]
      desc    = "Only domain users in IAM policies"
    }
  }
}

resource "google_org_policy_policy" "boolean" {
  for_each = local.boolean_policies
  name     = "organizations/${var.org_id}/policies/${each.key}"
  parent   = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = each.value.enforce ? "TRUE" : "FALSE"
    }
  }
}

resource "google_org_policy_policy" "list" {
  for_each = local.list_policies
  name     = "organizations/${var.org_id}/policies/${each.key}"
  parent   = "organizations/${var.org_id}"

  spec {
    rules {
      values {
        allowed_values = each.value.allowed
      }
    }
  }
}

output "enforced_policies" {
  value = [for k, v in local.boolean_policies : k]
}

output "list_policies" {
  value = [for k, v in local.list_policies : k]
}
