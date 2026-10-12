# /// script
# requires-python = ">=3.11"
# dependencies = ["fastmcp>=4,<5"]
# ///
"""Read-only MCP server: a buyer's agent can read the vendor's answers and their latest check results.

It serves a recorded snapshot, never runs checks or changes anything.
Run python3 run_checks.py to refresh report.json.
"""
import json
from pathlib import Path

from fastmcp import FastMCP

REPORT = Path(__file__).parent / "report.json"
mcp = FastMCP("rfp-sandbox")


def load():
    if not REPORT.exists():
        raise FileNotFoundError("No report yet. Run python3 run_checks.py first.")
    return json.loads(REPORT.read_text())


@mcp.tool
def list_claims() -> dict:
    """List recorded results as of generated_at; these are not live assessments."""
    report = load()
    return {"generated_at": report["generated_at"], "scope": report["scope"],
            "claims": [{"id": r["id"], "question": r["question"], "status": r["status"]}
                       for r in report["results"]]}


@mcp.tool
def get_answer(claim_id: str) -> dict:
    """Return the vendor's approved answer for one claim, the check result, and where the evidence came from."""
    report = load()
    for r in report["results"]:
        if r["id"] == claim_id:
            provenance = {k: report[k] for k in (
                "generated_at", "sandbox_version", "source_sha256", "identity_provider", "data", "mode", "scope"
            )}
            return {**r, "report": provenance}
    raise ValueError(f"Unknown claim: {claim_id}. Call list_claims for valid ids.")


if __name__ == "__main__":
    mcp.run()
