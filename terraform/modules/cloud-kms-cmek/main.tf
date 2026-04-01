# ──────────────────────────────────────────────────────────────
# Module: cloud-kms-cmek
# Purpose: KMS keyrings and keys per environment.
#          HSM for prod. 365-day automated rotation.
# ADR:     ADR-005
# ──────────────────────────────────────────────────────────────

variable "project_id" { type = string }
variable "region" { type = string; default = "us-central1" }
variable "environments" { type = list(string); default = ["prod", "nonprod", "shared"] }
variable "rotation_period" { type = string; default = "31536000s" } # 365 days

locals {
  key_purposes = {
    "phi-data"     = "Encrypt PHI at rest in GCS and BigQuery"
    "gke-secrets"  = "Encrypt GKE secrets (etcd)"
    "cloud-sql"    = "Encrypt Cloud SQL instances"
    "audit-logs"   = "Encrypt audit log archives"
    "pubsub"       = "Encrypt Pub/Sub messages"
  }
}

resource "google_kms_key_ring" "keyrings" {
  for_each = toset(var.environments)
  project  = var.project_id
  name     = "${each.value}-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "keys" {
  for_each = { for pair in setproduct(var.environments, keys(local.key_purposes)) :
    "${pair[0]}-${pair[1]}" => {
      env     = pair[0]
      purpose = pair[1]
    }
  }

  name     = each.value.purpose
  key_ring = google_kms_key_ring.keyrings[each.value.env].id

  rotation_period = var.rotation_period
  purpose         = "ENCRYPT_DECRYPT"

  # Use HSM for prod, software for non-prod
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = each.value.env == "prod" ? "HSM" : "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# ── IAM: Grant encrypter/decrypter to service accounts ────────
resource "google_kms_crypto_key_iam_member" "encrypters" {
  for_each = { for pair in setproduct(var.environments, keys(local.key_purposes)) :
    "${pair[0]}-${pair[1]}" => {
      env     = pair[0]
      purpose = pair[1]
    }
  }

  crypto_key_id = google_kms_crypto_key.keys[each.key].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@compute-system.iam.gserviceaccount.com"
}

data "google_project" "project" {
  project_id = var.project_id
}

output "keyring_ids" {
  value = { for k, v in google_kms_key_ring.keyrings : k => v.id }
}

output "key_ids" {
  value = { for k, v in google_kms_crypto_key.keys : k => v.id }
}
