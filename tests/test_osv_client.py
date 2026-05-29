"""Tests for the OSV.dev async client."""

import httpx
import pytest
import respx

from gitexpose.supply_chain import Dependency
from gitexpose.supply_chain.osv import query_osv

QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/GHSA-xxxx"


def _dep(name="lodash", version="4.17.20", eco="npm"):
    return Dependency(name=name, version=version, ecosystem=eco,
                      purl=f"pkg:npm/{name}@{version}", direct=True, source_file="package-lock.json")


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_maps_vuln_to_dependency():
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-xxxx", "modified": "2026-01-01"}]}]}))
    respx.get(VULN).mock(return_value=httpx.Response(200, json={
        "id": "GHSA-xxxx",
        "summary": "Prototype pollution in lodash",
        "aliases": ["CVE-2020-8203"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }))
    dep = _dep()
    result = await query_osv([dep])
    vulns = result[dep.purl]
    assert vulns[0].vuln_id == "GHSA-xxxx"
    assert vulns[0].severity == "HIGH"
    assert vulns[0].fixed_version == "4.17.21"
    assert "CVE-2020-8203" in vulns[0].aliases


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_no_vulns_returns_empty():
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    dep = _dep()
    result = await query_osv([dep])
    assert result.get(dep.purl, []) == []


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_network_error_degrades_to_empty():
    respx.post(QUERYBATCH).mock(side_effect=httpx.ConnectError("down"))
    dep = _dep()
    result = await query_osv([dep])
    assert result == {}   # degrade gracefully; caller falls back to curated list


@pytest.mark.asyncio
@respx.mock
async def test_query_osv_respects_max_deps():
    route = respx.post(QUERYBATCH).mock(return_value=httpx.Response(200, json={"results": [{}]}))
    deps = [_dep(name=f"p{i}", version="1.0.0") for i in range(10)]
    await query_osv(deps, max_deps=3)
    # Only one batch request was sent (3 ≤ 1000 per batch), proving truncation happened.
    sent = route.calls.last.request
    import json as _json
    body = _json.loads(sent.content)
    assert len(body["queries"]) == 3
