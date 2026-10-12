# The integration a customer's identity admin reviews before `terraform apply`:
# one app registration, two groups and three test users. Nothing else.
terraform {
  required_providers {
    keycloak = { source = "keycloak/keycloak", version = "~> 5.0" }
    random   = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

variable "idp_url" {
  type    = string
  default = "http://localhost:8080"
  validation {
    condition     = var.idp_url == "http://localhost:8080"
    error_message = "This demo uses local bootstrap credentials and only supports http://localhost:8080."
  }
}

variable "disabled_users" {
  description = "Test users to disable. The deprovisioning check sets this, then clears it."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for user in var.disabled_users : user == "carol"])
    error_message = "Only the disposable carol test user may be disabled by this demo."
  }
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = "admin"
  password  = "admin"
  url       = var.idp_url
}

locals {
  users = { alice = "vendor-admins", bob = "vendor-viewers", carol = "vendor-viewers" }
}

resource "keycloak_realm" "customer" {
  realm = "customer"
}

resource "keycloak_openid_client" "vendor_app" {
  realm_id    = keycloak_realm.customer.id
  client_id   = "vendor-app"
  access_type = "CONFIDENTIAL"
  # ponytail: password grant lets the checks sign in headlessly; real users get authorization code + PKCE.
  direct_access_grants_enabled = true
}

resource "keycloak_openid_audience_protocol_mapper" "audience" {
  realm_id                 = keycloak_realm.customer.id
  client_id                = keycloak_openid_client.vendor_app.id
  name                     = "audience"
  included_client_audience = keycloak_openid_client.vendor_app.client_id
}

resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id   = keycloak_realm.customer.id
  client_id  = keycloak_openid_client.vendor_app.id
  name       = "groups"
  claim_name = "groups"
  full_path  = false
  # The app checks group membership via introspection, so the claim must be included there too.
  add_to_token_introspection = true
}

resource "keycloak_group" "group" {
  for_each = toset(values(local.users))
  realm_id = keycloak_realm.customer.id
  name     = each.key
}

resource "random_password" "test_users" {
  length  = 24
  special = false
}

resource "keycloak_user" "user" {
  for_each       = local.users
  realm_id       = keycloak_realm.customer.id
  username       = each.key
  enabled        = !contains(var.disabled_users, each.key)
  email          = "${each.key}@example.test"
  email_verified = true
  first_name     = title(each.key)
  last_name      = "Test"

  initial_password {
    value     = random_password.test_users.result
    temporary = false
  }
}

resource "keycloak_user_groups" "membership" {
  for_each  = local.users
  realm_id  = keycloak_realm.customer.id
  user_id   = keycloak_user.user[each.key].id
  group_ids = [keycloak_group.group[each.value].id]
}

output "issuer" {
  value = "${var.idp_url}/realms/${keycloak_realm.customer.realm}"
}

output "client_id" {
  value = keycloak_openid_client.vendor_app.client_id
}

output "client_secret" {
  value     = keycloak_openid_client.vendor_app.client_secret
  sensitive = true
}

output "test_password" {
  value     = random_password.test_users.result
  sensitive = true
}
