# Evaluation report

Generated 2026-10-12T19:52:06+03:00 · sandbox `sha256:50ed0a8933fe46f85abb17cdab16053a7b060204c704f3522ebcb19c7d0aee5b` · identity provider `http://localhost:8080/realms/customer` · synthetic data. Results apply to this sandbox, not production.

| Question | Vendor's answer | Result | Evidence |
| --- | --- | --- | --- |
| Can the sample authenticate with the bundled identity provider? | Yes. It obtains and introspects a token from the local Keycloak realm. | ✅ supported | Test user signed in. Token issuer http://localhost:8080/realms/customer, audience vendor-app, account |
| Can groups control the sample's authorization decisions? | Yes. Test groups map to read and export permissions in the sample function. | ✅ supported | admin export: allowed; viewer read: allowed; viewer export: denied |
| Does disabling the test user block token requests and access? | Yes. After disabling, new token requests fail and the sample rejects the old token. | ✅ supported | After disabling a test user: new token request blocked; previous token rejected by the sample authorization function |
| Is MFA enforced for privileged accounts? | Yes, for every privileged account. | ❌ contradicted | 11/12 privileged accounts with MFA (synthetic sign-in log sample, 2026-10-10). Exceptions: admin-07 |
| Can we export audit logs? | Yes, a daily export to customer storage. | ⏳ stale | Evidence is 253 days old: 30/30 daily exports delivered (synthetic export job history, 2026-02-01) |
| Is customer data encrypted at rest? | Yes, with AES-256. | ❔ unknown | Nothing to check: attested only. Needs a document and human review. |
