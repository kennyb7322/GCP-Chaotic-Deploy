# ──────────────────────────────────────────────────────────────
# OPA Conftest Policies — HIPAA Guardrails for Terraform
# These policies run in the CI/CD pipeline (deploy.yml) as a
# mandatory gate before any terraform apply.
# ──────────────────────────────────────────────────────────────

package main

import future.keywords.in

# ── P-001: No public GCS buckets ──────────────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    not resource.change.after.uniform_bucket_level_access
    msg := sprintf("P-001: Bucket '%s' must enable uniform_bucket_level_access [HIPAA §164.312(a)(1)]", [resource.name])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_storage_bucket"
    resource.change.after.public_access_prevention != "enforced"
    msg := sprintf("P-001: Bucket '%s' must set public_access_prevention=enforced [HIPAA]", [resource.name])
}

# ── P-002: CMEK required for PHI resources ────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_bigquery_dataset", "google_storage_bucket", "google_sql_database_instance"]
    labels := object.get(resource.change.after, "labels", {})
    labels.compliance == "hipaa"
    not resource.change.after.encryption_configuration
    msg := sprintf("P-002: Resource '%s' with HIPAA label must use CMEK [ADR-005]", [resource.name])
}

# ── P-003: No external IPs on VMs ────────────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_instance"
    access_config := resource.change.after.network_interface[_].access_config
    count(access_config) > 0
    msg := sprintf("P-003: VM '%s' must not have external IP [Org Policy]", [resource.name])
}

# ── P-004: VPC flow logs required ─────────────────────────────
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_subnetwork"
    not resource.change.after.log_config
    msg := sprintf("P-004: Subnet '%s' should enable VPC flow logs [HIPAA §164.312(b)]", [resource.name])
}

# ── P-005: Labels required ────────────────────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_project", "google_compute_instance", "google_storage_bucket"]
    labels := object.get(resource.change.after, "labels", {})
    not labels.managed_by
    msg := sprintf("P-005: Resource '%s' must have 'managed_by' label", [resource.name])
}

# ── P-006: KMS keys must have rotation ────────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_kms_crypto_key"
    not resource.change.after.rotation_period
    msg := sprintf("P-006: KMS key '%s' must have rotation_period set [ADR-005]", [resource.name])
}

# ── P-007: No SA key creation ─────────────────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_service_account_key"
    msg := sprintf("P-007: SA key '%s' creation blocked — use WIF [ADR-015]", [resource.name])
}

# ── P-008: US region only ─────────────────────────────────────
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["google_compute_subnetwork", "google_kms_key_ring", "google_storage_bucket"]
    location := object.get(resource.change.after, "location", object.get(resource.change.after, "region", ""))
    not startswith(location, "us-")
    not location == "US"
    msg := sprintf("P-008: Resource '%s' must be in US region [Assured Workloads]", [resource.name])
}
