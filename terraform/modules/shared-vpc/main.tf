# ──────────────────────────────────────────────────────────────
# Module: shared-vpc
# Purpose: Hub-spoke Shared VPC with centralized firewall,
#          Private Service Access, HA VPN, and chaos subnet.
# ADRs:    ADR-003, ADR-014
# ──────────────────────────────────────────────────────────────

variable "org_id" { type = string }
variable "host_project_id" { type = string }
variable "region" { type = string; default = "us-central1" }
variable "service_projects" { type = list(string); default = [] }

variable "subnets" {
  type = map(object({
    cidr            = string
    secondary_ranges = optional(map(string), {})
    purpose         = optional(string, "PRIVATE")
    private_access  = optional(bool, true)
    flow_logs       = optional(bool, true)
  }))
  default = {
    "prod-workloads" = {
      cidr = "10.10.0.0/20"
      secondary_ranges = {
        gke-pods     = "10.20.0.0/16"
        gke-services = "10.30.0.0/20"
      }
    }
    "nonprod-workloads" = {
      cidr = "10.11.0.0/20"
      secondary_ranges = {
        gke-pods     = "10.21.0.0/16"
        gke-services = "10.31.0.0/20"
      }
    }
    "shared-services" = {
      cidr = "10.12.0.0/22"
    }
    "chaos-engineering" = {
      cidr = "10.13.0.0/24"
    }
  }
}

# ── Shared VPC Host ────────────────────────────────────────────
resource "google_compute_shared_vpc_host_project" "host" {
  project = var.host_project_id
}

resource "google_compute_shared_vpc_service_project" "service" {
  for_each        = toset(var.service_projects)
  host_project    = google_compute_shared_vpc_host_project.host.project
  service_project = each.value
}

# ── VPC Network ────────────────────────────────────────────────
resource "google_compute_network" "vpc" {
  project                 = var.host_project_id
  name                    = "shared-vpc"
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
  mtu                     = 1460
}

# ── Subnets ────────────────────────────────────────────────────
resource "google_compute_subnetwork" "subnets" {
  for_each = var.subnets

  project       = var.host_project_id
  name          = each.key
  network       = google_compute_network.vpc.self_link
  region        = var.region
  ip_cidr_range = each.value.cidr
  purpose       = each.value.purpose

  private_ip_google_access = each.value.private_access

  dynamic "secondary_ip_range" {
    for_each = each.value.secondary_ranges
    content {
      range_name    = secondary_ip_range.key
      ip_cidr_range = secondary_ip_range.value
    }
  }

  dynamic "log_config" {
    for_each = each.value.flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# ── Cloud NAT ──────────────────────────────────────────────────
resource "google_compute_router" "nat_router" {
  project = var.host_project_id
  name    = "nat-router"
  network = google_compute_network.vpc.self_link
  region  = var.region
}

resource "google_compute_router_nat" "nat" {
  project = var.host_project_id
  name    = "cloud-nat"
  router  = google_compute_router.nat_router.name
  region  = var.region

  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ── Private Service Access (Cloud SQL, Memstore, etc.) ─────────
resource "google_compute_global_address" "psa_range" {
  project       = var.host_project_id
  name          = "psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.vpc.self_link
}

resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.vpc.self_link
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa_range.name]
}

# ── Outputs ────────────────────────────────────────────────────
output "network_self_link" {
  value = google_compute_network.vpc.self_link
}

output "subnet_self_links" {
  value = { for k, v in google_compute_subnetwork.subnets : k => v.self_link }
}

output "network_name" {
  value = google_compute_network.vpc.name
}
