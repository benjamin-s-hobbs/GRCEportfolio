# terraform/baseline/gcp/main.tf
# org policy at project level
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "civic-access-392521"
  region  = "us-central1"
}
resource "google_org_policy_policy" "uniform_bucket_access" {
  name   = "projects/${var.gcp_project}/policies/storage.uniformBucketLevelAccess"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

resource "google_org_policy_policy" "disable_sa_keys" {
  name   = "projects/${var.gcp_project}/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

resource "google_org_policy_policy" "require_oslogin" {
  name   = "projects/${var.gcp_project}/policies/compute.requireOsLogin"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}


# Workload Identity Federation
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.actor"      = "assertion.actor"
  }

  attribute_condition = "assertion.repository == \"GRCEngClub/cgep-app-starter\""

  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

resource "google_service_account" "gha" {
  account_id   = "cgep-grc-gate-sa"
  display_name = "CGE-P GRC gate (read-only)"
}

resource "google_project_iam_member" "gha_viewer" {
  project = var.gcp_project
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.gha.email}"
}

resource "google_service_account_iam_binding" "wif_user" {
  service_account_id = google_service_account.gha.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/GRCEngClub/cgep-app-starter",
  ]
}