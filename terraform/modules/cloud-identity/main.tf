# Module: cloud-identity
# See README.md for full documentation
variable "org_id" { type = string }
variable "region" { type = string; default = "us-central1" }
variable "labels" { type = map(string); default = {} }
