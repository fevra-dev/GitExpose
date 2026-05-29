"""Tests for the CycloneDX 1.6 AI-BOM reporter."""

import json

from gitexpose.supply_chain import Dependency
from gitexpose.reporters.cyclonedx_reporter import build_bom


def _dep(name="lodash", version="4.17.20"):
    return Dependency(name=name, version=version, ecosystem="npm",
                      purl=f"pkg:npm/{name}@{version}", direct=True,
                      source_file="package-lock.json", integrity_hash="sha512-AAAA")


def test_build_bom_is_valid_cyclonedx_json():
    deps = [_dep()]
    findings = [{
        "type": "vulnerable_dependency", "package": "lodash", "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20", "vuln_id": "GHSA-xxxx", "severity": "HIGH",
        "cvss_score": 7.5, "summary": "proto pollution",
        "advisory_url": "https://osv.dev/vulnerability/GHSA-xxxx",
        "cred_co_present": False, "direct": True, "pinned": False,
    }]
    out = build_bom(deps, findings)
    doc = json.loads(out)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    # NTIA minimum elements
    assert doc["metadata"]["timestamp"]
    assert doc["metadata"]["tools"]
    names = {c["name"] for c in doc["components"]}
    assert "lodash" in names
    # VEX entry present, honestly scoped to in_triage by default
    vex = doc["vulnerabilities"][0]
    assert vex["id"] == "GHSA-xxxx"
    assert vex["analysis"]["state"] == "in_triage"


def test_vex_state_exploitable_only_on_verified_cred_copresence():
    deps = [_dep()]
    findings = [{
        "type": "vulnerable_dependency", "package": "lodash", "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20", "vuln_id": "GHSA-xxxx", "severity": "HIGH",
        "summary": "x", "advisory_url": "https://osv.dev/vulnerability/GHSA-xxxx",
        "cred_co_present": True, "direct": True, "pinned": False, "known_exploited": False,
        "verification_status": "verified",
    }]
    doc = json.loads(build_bom(deps, findings))
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "exploitable"
