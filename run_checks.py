#!/usr/bin/env python3
"""Check each vendor claim and write report.json + report.md. Standard library only.

Results: supported, contradicted, stale (evidence too old) or unknown (nothing to check).
"""
import argparse
import base64
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent
SOURCE_FILES = (
    "run_checks.py", "server.py", "claims.json", "compose.yaml",
    "terraform/main.tf", "terraform/.terraform.lock.hcl",
    "evidence/admin-mfa.json", "evidence/audit-export.json",
)
MAX_EVIDENCE_AGE_DAYS = 90
# The vendor app's authorization policy: identity-provider group -> allowed actions.
PERMISSIONS = {"vendor-admins": {"read", "export"}, "vendor-viewers": {"read"}}
ICONS = {"supported": "✅", "contradicted": "❌", "stale": "⏳", "unknown": "❔"}


def evaluate(evidence, as_of):
    if evidence is None:
        return "unknown", "Nothing to check: attested only. Needs a document and human review."
    observed = datetime.fromisoformat(evidence["observed_at"]).date()
    total, passing = evidence["total"], evidence["passing"]
    if type(total) is not int or type(passing) is not int or total <= 0 or not 0 <= passing <= total:
        return "unknown", "Invalid or empty evidence counts; no claim can be supported."
    if observed > as_of:
        return "unknown", "Evidence is dated in the future; check its provenance."
    seen = f"{evidence['passing']}/{evidence['total']} {evidence['scope']} ({evidence['source']}, {observed})"
    if (as_of - observed).days > MAX_EVIDENCE_AGE_DAYS:
        return "stale", f"Evidence is {(as_of - observed).days} days old: {seen}"
    if evidence["passing"] == evidence["total"]:
        return "supported", seen
    return "contradicted", f"{seen}. Exceptions: {', '.join(evidence['exceptions'])}"


# --- Identity checks against the live sandbox -------------------------------------------

def terraform(*args):
    return subprocess.run(["terraform", f"-chdir={ROOT / 'terraform'}", *args],
                          check=True, capture_output=True, text=True).stdout


def idp_config():
    try:
        out = json.loads(terraform("output", "-json"))
        config = {k: v["value"] for k, v in out.items()} if out else None
        if config and (config["issuer"] != "http://localhost:8080/realms/customer"
                       or config["client_id"] != "vendor-app"):
            raise ValueError("Only the bundled local customer realm and vendor-app client are supported.")
        return config
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"Cannot load sandbox configuration: {error}", file=sys.stderr)
        return None


def post(url, data, idp):
    auth = base64.b64encode(f"{idp['client_id']}:{idp['client_secret']}".encode()).decode()
    req = urllib.request.Request(url, urllib.parse.urlencode(data).encode(),
                                 {"Authorization": f"Basic {auth}"})
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.load(res)


def sign_in(user, idp):
    return post(f"{idp['issuer']}/protocol/openid-connect/token", {
        "grant_type": "password", "scope": "openid",
        "username": user, "password": idp["test_password"]}, idp)["access_token"]


def introspect(token, idp):
    return post(f"{idp['issuer']}/protocol/openid-connect/token/introspect", {"token": token}, idp)


def audiences(claims):
    aud = claims.get("aud") or []
    return [aud] if isinstance(aud, str) else aud


def authorize(token, action, idp):
    """A sample authorization function, not a deployed vendor application's endpoint."""
    claims = introspect(token, idp)
    if not claims.get("active") or claims.get("iss") != idp["issuer"] or idp["client_id"] not in audiences(claims):
        return False
    return any(action in PERMISSIONS.get(group, ()) for group in claims.get("groups", []))


def check_oidc_sign_in(idp):
    claims = introspect(sign_in("alice", idp), idp)
    ok = claims.get("active") and claims.get("iss") == idp["issuer"] and idp["client_id"] in audiences(claims)
    return ("supported" if ok else "contradicted",
            f"Test user signed in. Token issuer {claims.get('iss')}, audience {', '.join(audiences(claims))}")


def check_group_permissions(idp):
    alice, bob = sign_in("alice", idp), sign_in("bob", idp)
    got = {"admin export": authorize(alice, "export", idp),
           "viewer read": authorize(bob, "read", idp),
           "viewer export": authorize(bob, "export", idp)}
    want = {"admin export": True, "viewer read": True, "viewer export": False}
    return ("supported" if got == want else "contradicted",
            "; ".join(f"{k}: {'allowed' if v else 'denied'}" for k, v in got.items()))


def check_revocation(idp):
    # ponytail: disables a sandbox test user through the same Terraform the customer reviewed, then restores it.
    token = sign_in("carol", idp)
    if not authorize(token, "read", idp):
        return "unknown", "Test user had no access before disabling; revocation cannot be established."
    try:
        terraform("apply", "-auto-approve", "-input=false", '-var=disabled_users=["carol"]')
        old_token = authorize(token, "read", idp)
        try:
            sign_in("carol", idp)
            new_sign_in = True
        except urllib.error.HTTPError as error:
            if error.code != 400 or json.load(error).get("error") != "invalid_grant":
                raise
            new_sign_in = False
    finally:
        try:
            terraform("apply", "-auto-approve", "-input=false", "-var=disabled_users=[]")
        except (OSError, subprocess.CalledProcessError) as error:
            raise RuntimeError("Could not restore the test users. Inspect Terraform state before retrying.") from error
    ok = not old_token and not new_sign_in
    return ("supported" if ok else "contradicted",
            f"After disabling a test user: new token request {'succeeded' if new_sign_in else 'blocked'}; "
            f"previous token {'still accepted' if old_token else 'rejected'} by the sample authorization function")


CHECKS = {"oidc_sign_in": check_oidc_sign_in, "group_permissions": check_group_permissions,
          "revocation": check_revocation}


def run(claim, idp, as_of, check_revocation_enabled=False):
    if "check" in claim:
        if idp is None:
            return "unknown", "No live sandbox configuration loaded (offline or not deployed)."
        if claim["check"] == "revocation" and not check_revocation_enabled:
            return "unknown", "Mutation skipped. Use --check-revocation only in the disposable local sandbox."
        try:
            return CHECKS[claim["check"]](idp)
        except (OSError, subprocess.CalledProcessError) as error:
            return "unknown", f"Check could not run: {error}"
    evidence = claim.get("evidence")
    return evaluate(json.loads((ROOT / evidence).read_text()) if evidence else None, as_of)


def main(args):
    now = datetime.now(timezone.utc).astimezone()
    idp = None if args.offline else idp_config()
    results = []
    for claim in json.loads((ROOT / "claims.json").read_text()):
        status, detail = run(claim, idp, now.date(), args.check_revocation)
        results.append({**claim, "status": status, "detail": detail})
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}
    version = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    report = {"generated_at": now.isoformat(timespec="seconds"), "sandbox_version": f"sha256:{version}",
              "source_sha256": hashes, "identity_provider": idp["issuer"] if idp else "not connected",
              "data": "synthetic", "mode": "offline" if args.offline else "local",
              "scope": "Keycloak password-grant and token-introspection smoke checks plus synthetic fixtures. "
                       "Not browser SSO, a deployed vendor application, SCIM, or production certification.",
              "results": results}
    (ROOT / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    lines = ["# Evaluation report", "",
             f"Generated {report['generated_at']} · sandbox `{report['sandbox_version']}` · "
             f"identity provider `{report['identity_provider']}` · synthetic data. "
             "Results apply to this sandbox, not production.", "",
             "| Question | Vendor's answer | Result | Evidence |", "| --- | --- | --- | --- |"]
    lines += [f"| {r['question']} | {r['answer']} | {ICONS[r['status']]} {r['status']} | {r['detail']} |"
              for r in results]
    (ROOT / "report.md").write_text("\n".join(lines) + "\n")
    for r in results:
        print(f"{ICONS[r['status']]} {r['status']:<12} {r['id']}")


def self_test():
    from io import BytesIO
    from unittest.mock import patch

    as_of = date(2026, 10, 12)
    fresh = {"source": "s", "observed_at": "2026-10-10T00:00:00Z", "scope": "x", "total": 2, "passing": 2, "exceptions": []}
    assert evaluate(fresh, as_of)[0] == "supported"
    assert evaluate({**fresh, "passing": 1, "exceptions": ["a"]}, as_of)[0] == "contradicted"
    assert evaluate({**fresh, "observed_at": "2026-01-01T00:00:00Z"}, as_of)[0] == "stale"
    assert evaluate({**fresh, "observed_at": "2026-01-01T00:00:00Z", "passing": 1, "exceptions": ["a"]}, as_of)[0] == "stale"
    assert evaluate(None, as_of)[0] == "unknown"
    assert evaluate({**fresh, "total": 0, "passing": 0}, as_of)[0] == "unknown"
    assert evaluate({**fresh, "passing": 3}, as_of)[0] == "unknown"
    assert evaluate({**fresh, "observed_at": "2027-01-01T00:00:00Z"}, as_of)[0] == "unknown"
    assert evaluate({**fresh, "observed_at": "2026-07-14T00:00:00Z"}, as_of)[0] == "supported"
    assert evaluate({**fresh, "observed_at": "2026-07-13T00:00:00Z"}, as_of)[0] == "stale"
    assert audiences({"aud": "a"}) == ["a"] and audiences({}) == []
    module = sys.modules[__name__]
    idp = {"issuer": "local", "client_id": "test"}
    valid = {"active": True, "iss": "local", "aud": "test", "groups": ["vendor-admins"]}
    for overrides, expected in [
        ({}, True), ({"active": False}, False), ({"iss": "wrong"}, False),
        ({"aud": "wrong"}, False), ({"groups": ["vendor-viewers"]}, False),
        ({"groups": []}, False),
    ]:
        with patch.object(module, "introspect", return_value={**valid, **overrides}):
            assert authorize("token", "export", idp) is expected
    for groups, expected in [(["vendor-admins"], "supported"), ([], "contradicted")]:
        with patch.object(module, "sign_in", side_effect=["alice", "bob"]), patch.object(
            module, "introspect",
            side_effect=lambda token, _: {**valid, "groups": groups if token == "alice" else ["vendor-viewers"]},
        ):
            assert check_group_permissions(idp)[0] == expected
    assert run({"check": "revocation"}, idp, as_of)[0] == "unknown"
    with patch.object(module, "sign_in", return_value="token"), patch.object(
        module, "authorize", return_value=False
    ), patch.object(module, "terraform") as tf:
        assert check_revocation(idp)[0] == "unknown"
        tf.assert_not_called()
    for status, error_body, expected in [
        (400, b'{"error":"invalid_grant"}', "supported"),
        (500, b'{"error":"server_error"}', "unknown"),
        (401, b'{"error":"invalid_client"}', "unknown"),
    ]:
        failure = urllib.error.HTTPError("local", status, "test", {}, BytesIO(error_body))
        with patch.object(module, "sign_in", side_effect=["token", failure]), patch.object(
            module, "authorize", side_effect=[True, False]
        ), patch.object(module, "terraform") as tf:
            assert run({"check": "revocation"}, idp, as_of, True)[0] == expected
            assert tf.call_count == 2
            assert tf.call_args.args[-1] == "-var=disabled_users=[]"
    with patch.object(module, "sign_in", return_value="token"), patch.object(
        module, "authorize", return_value=True
    ), patch.object(module, "terraform", side_effect=[OSError("apply failed"), ""]) as tf:
        assert run({"check": "revocation"}, idp, as_of, True)[0] == "unknown"
        assert tf.call_count == 2
    with patch.object(module, "sign_in", return_value="token"), patch.object(
        module, "authorize", return_value=True
    ), patch.object(module, "terraform", side_effect=["", OSError("restore failed")]):
        try:
            check_revocation(idp)
        except RuntimeError as error:
            assert "Could not restore" in str(error)
        else:
            raise AssertionError("Restoration failure must stop the run")
    print("self-test ok")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run offline regression checks")
    parser.add_argument("--offline", action="store_true", help="Use fixtures only; identity checks stay unknown")
    parser.add_argument("--check-revocation", action="store_true",
                        help="Allow Terraform to disable and restore the disposable local carol test user")
    args = parser.parse_args()
    if args.offline and args.check_revocation:
        parser.error("--offline cannot be combined with --check-revocation")
    self_test() if args.self_test else main(args)
