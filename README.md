# RFP sandbox

An experiment: what if a vendor's RFP answers came with a sandbox that checks them?

`claims.json` holds a fictional vendor's approved answers. `run_checks.py` checks each one and reports
**supported**, **contradicted**, **stale** (evidence too old) or **unknown** (nothing to check).
Everything is synthetic and runs on your machine. See [`report.md`](report.md) for a sample run.

## Run it

Needs Docker Compose with `--wait` support, Terraform and Python 3.11+.
Use a disposable local environment with port 8080 free. The bootstrap admin is
deliberately local-only; never deploy this configuration on a public network.

```bash
git clone https://github.com/ragmha/rfp-sandbox && cd rfp-sandbox
docker compose up -d --wait                    # stand-in for your existing identity provider
terraform -chdir=terraform init
terraform -chdir=terraform apply               # review, then register the app, groups and test users
python3 run_checks.py --check-revocation        # writes report.md and report.json
```

`--check-revocation` explicitly allows two Terraform applies: disable the synthetic
`carol` user, then restore her. Without the flag that check stays `unknown`.
If restoration fails, the run stops rather than writing a success-shaped report.
Never connect real identities. Terraform state contains generated test credentials;
do not upload state, provider directories, or `.tfvars` files.

No infrastructure needed for the offline checks:

```bash
python3 run_checks.py --self-test
python3 run_checks.py --offline
```

Offline runs label all identity checks `unknown`; they do not fabricate passing
integrations. Evidence older than 90 days is stale, so results change with time.
Each report records its timestamp, scope, and hashes of the source/configuration.
Both commands that generate reports replace `report.json` and `report.md`.

## What's here

| File | Role |
| --- | --- |
| `claims.json` | The vendor's approved answers, each with an owner, review date and a check or evidence file |
| `terraform/main.tf` | The identity integration a customer reviews before applying: one app, two groups, three test users |
| `evidence/` | Synthetic observations, standing in for a log store such as Kusto |
| `run_checks.py` | Checks password-grant tokens, a sample authorization function, optional user disablement, and fixture freshness |
| `server.py` | Read-only MCP server so a buyer's agent can read answers and results; it never runs checks |

## Connect an agent

Install `uv` separately if you want the optional MCP server. It resolves the
FastMCP dependency declared in `server.py`; the report generator needs no packages.

```json
{ "mcpServers": { "rfp-sandbox": { "command": "uv", "args": ["run", "/path/to/rfp-sandbox/server.py"] } } }
```

Tools: `list_claims` and `get_answer`. These serve a recorded snapshot, not a fresh
assessment. Both expose its timestamp; each answer includes source hashes and scope.
Keep this a local stdio server, not an unauthenticated remote endpoint.

## Customer-hosted direction, not a feature claim

Only the bundled local Keycloak realm is supported. Entra ID, Okta, and customer
VPC/VNet deployments would need different provider resources, identity flows,
networking, authorization, and new checks. Replacing a Terraform provider name
is not enough. The claim/result format is the reusable part of the experiment.

## Clean up

After reviewing the evidence, destroy only the disposable resources created here:

```bash
terraform -chdir=terraform destroy
docker compose down
```

If interrupted during revocation, re-enable the test user before continuing:
`terraform -chdir=terraform apply -var='disabled_users=[]'`.
The Compose database is disposable; do not stop it before `terraform destroy`.

## Limits

- Results apply to this sandbox and its synthetic data, not to any production system.
- Identity checks use Keycloak's password grant and token introspection. This is not a
  browser SSO, PKCE, MFA challenge, or cross-provider compatibility test.
- Group checks exercise a Python authorization function, not a deployed app or export endpoint.
- The revocation check observes token rejection after a Terraform apply; it does not measure an
  instantaneous revocation guarantee, browser session termination, or SCIM provisioning.
- MFA and audit-export results come from hand-authored synthetic fixtures, not live collectors.
- This sample cannot verify encryption at rest; it stays `unknown` pending an appropriate review.
- Not built yet: SCIM provisioning, agent-to-agent (A2A) exchange, a gateway, and cloud deployment.

## License

[MIT](LICENSE)
