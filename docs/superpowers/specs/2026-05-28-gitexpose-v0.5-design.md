# GitExpose v0.5 — "Supply-Chain Intelligence" Design

> Brainstormed 2026-05-28. Headline: turn GitExpose's static supply-chain signatures into
> real dependency SCA — parse lock files, query OSV.dev for live vulnerability intelligence,
> and export a CycloneDX 1.6 AI-BOM with honestly-scoped VEX.

## 1. Motivation

GitExpose's supply-chain pack today is entirely **static signatures**: a hard-coded
`KNOWN_BAD_VERSIONS` list of ~6 packages, a fixed `slopsquatting` corpus, and a fixed
AI-middleware allowlist for pinning checks. This is the product's thinnest area — it goes
stale the moment a new advisory lands.

v0.5 fixes the root cause by adding a real dependency-vulnerability pipeline:

1. **Lock-file parsing** builds an actual dependency inventory.
2. **OSV.dev** enriches every dependency with live CVE/GHSA/malicious-package advisories
   (free, no-auth, batch async).
3. **CycloneDX 1.6 AI-BOM** export carries that inventory + findings + VEX as a portable artifact.

These three compose into one feature: inventory → live vuln data → exportable BOM-with-VEX.
The AI-BOM (flagged "thin" in the v0.4 notes because a BOM without vuln data is just a list)
becomes valuable precisely because OSV supplies the VEX data.

This is the same capability-jump shape as prior releases: v0.3 = Active Verification,
v0.4 = Detection Depth, v0.5 = Supply-Chain Intelligence.

### Scope decision: deepen, don't broaden

GitExpose stays in its lane — *exposure intelligence for AI and dev infrastructure*. v0.5
deepens the existing supply-chain surface for the ecosystems AI stacks actually live in
(Python + JS). It does **not** broaden into a general multi-ecosystem Trivy/Snyk competitor.
The Solana/Anchor research track is explicitly excluded (it belongs to a separate sister
product, per the v0.4 notes).

## 2. Scope

### In scope (v0.5)

- **Lock-file parsing** — Python (`requirements.txt`, `poetry.lock`, `Pipfile.lock`) and
  JavaScript (`package-lock.json` v2/v3, `yarn.lock` v1 + Berry).
- **OSV.dev live vuln lookups** — default on; `--offline` opt-out falls back to the curated
  `KNOWN_BAD_VERSIONS` list. Bounded fan-out via the batch API.
- **New finding type `vulnerable_dependency`** (CVE/GHSA/MAL) alongside the existing
  `known_malicious_package_version`.
- **CycloneDX 1.6 AI-BOM output** (`--output cyclonedx`, alias `aibom`) with components + VEX,
  built with `cyclonedx-python-lib`.
- **Exploitability-aware output** — lead with exploitability context (direct/transitive,
  fix-available, pinned, credential co-presence), not raw CVSS.

### Out of scope (deferred to v0.6+)

- Classic typosquatting (Levenshtein/Jaro-Winkler/homoglyph/keyboard) against popular-package
  baselines — complements existing slopsquatting; deferred.
- Lock-file **poisoning checks** — SRI hash mismatch, ghost dependencies (in lock, not in
  manifest), off-registry resolved URLs. **Note:** the v0.5 parser *captures* integrity hashes
  and resolved URLs (needed for BOM hashes), so these checks are cheap forward-compat in v0.6.
- Shai-Hulud / install-time behavioral analysis (npm lifecycle hooks, credential-harvesting
  AST, metadata-service SSRF, webhook.site exfil).
- Go (`go.sum`) and Cargo (`Cargo.lock`) ecosystems.
- Full code-reachability analysis (a research problem; v0.5 uses cheap exploitability *hints*).

## 3. Architecture

A new cohesive `gitexpose/supply_chain/` package, parallel to the existing `verification/`
and `git_history/` packages:

```
gitexpose/supply_chain/
  __init__.py
  models.py            # Dependency, Vulnerability dataclasses
  lockfiles/
    base.py            # parser registry + name normalization (PEP 503 / npm)
    python.py          # requirements.txt / poetry.lock / Pipfile.lock
    javascript.py      # package-lock.json / yarn.lock (v1 + Berry)
  osv.py               # async httpx batch client → OSV.dev
  correlate.py         # merge OSV results + curated KNOWN_BAD_VERSIONS → findings
gitexpose/reporters/cyclonedx_reporter.py   # CycloneDX 1.6 BOM builder
```

The existing `advanced/known_bad_versions.py`, `advanced/dependency_pinning.py`, and
`advanced/slopsquatting.py` are unchanged — they remain the curated/offline signal, and
`--offline` falls back to exactly them. OSV layers on top.

### Data model

```python
@dataclass
class Dependency:
    name: str                 # normalized (PEP 503 for Python, lowercase for npm)
    version: str
    ecosystem: str            # "PyPI" | "npm" (OSV ecosystem names)
    purl: str                 # pkg:pypi/...@... or pkg:npm/...@...
    direct: bool              # direct vs transitive (from lock file structure)
    source_file: str          # e.g. "poetry.lock"
    integrity_hash: str | None # captured for BOM hashes + v0.6 poisoning checks
    resolved_url: str | None   # captured for v0.6 poisoning checks

@dataclass
class Vulnerability:
    vuln_id: str              # CVE-… / GHSA-… / MAL-…
    severity: str             # CRITICAL|HIGH|MEDIUM|LOW (mapped from CVSS)
    cvss_score: float | None
    fixed_version: str | None
    summary: str
    advisory_url: str
    known_exploited: bool     # CISA KEV-style flag if OSV exposes it
```

## 4. CLI surface & data flow

Extends the existing `supply-chain` command (no new command):

```
gitexpose supply-chain <path> [options]
  -o, --output console|json|cyclonedx     # cyclonedx is new (alias: aibom)
  --out-file PATH                         # existing
  --offline                               # NEW: skip OSV, curated list only
  --osv-timeout 10.0                      # NEW: per-request timeout (seconds)
  --osv-max 5000                          # NEW: cap deps queried (bounds fan-out)
  --verify ...                            # existing credential verification, unchanged
```

Data flow:

```
supply-chain <path>
 1. LocalFilesystemScanner.scan()         # EXISTING: creds, AI configs, signatures,
                                           #   pinning, slopsquat, curated known-bad
 2. LockfileParser.parse_all(path)        # NEW: Dependency inventory
 3. if not --offline:
        OSVClient.query_batch(deps)       # NEW: POST /v1/querybatch (≤1000/req) → hydrate
    else:
        curated KNOWN_BAD_VERSIONS only   # offline fallback
 4. correlate()                           # NEW: emit vulnerable_dependency +
                                           #   known_malicious_package_version findings; merge
 5. --verify (existing)                   # creds → live provider check
 6. render
        console / json   (existing, + vulnerable_dependency lines, exploitability-ordered)
        cyclonedx         (NEW: full inventory + VEX)
 → exit 1 if findings else 0              # EXISTING contract.
                                           #   OSV network failure = warning, not failure.
```

**Bounded fan-out.** OSV `querybatch` accepts ≤1000 packages per request, so even a large
monorepo is a handful of requests. This structurally resolves the unbounded-fan-out concern
the v0.3 `/attack` audit raised for `--verify`. `--osv-max` is a belt-and-suspenders cap.

**Egress posture.** OSV lookups send dependency *names + versions* (not secrets) to Google's
OSV API. Default on (matches osv-scanner / Trivy norms) with a one-line egress notice;
`--offline` disables it entirely for air-gapped CI. This is lower-stakes than `--verify`
(which sends real credentials), so it does not require the blocking consent banner.

## 5. New finding type — `vulnerable_dependency`

```jsonc
{
  "type": "vulnerable_dependency",
  "package": "…", "version": "…", "ecosystem": "PyPI",
  "vuln_id": "CVE-… / GHSA-… / MAL-…",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",   // mapped from CVSS
  "cvss_score": 9.1,
  "fixed_version": "…",
  "summary": "…",
  "advisory_url": "https://osv.dev/vulnerability/…",
  "source": "poetry.lock",
  "direct": true,
  "pinned": false,
  "fix_available": true,
  "cred_co_present": false,                 // exploitability signal (see §6)
  "attack_class": "OWASP A06:2021 Vulnerable & Outdated Components",
  "atlas_technique": null,                  // set for AI-middleware packages
  "verification_status": "skipped"
}
```

### Compliance mapping

Existing findings carry OWASP LLM Top 10 + MITRE ATLAS. Vulnerable-dependency findings fit
**OWASP A06:2021 / CICD-SEC-3 (Dependency Chain Abuse)** better than the LLM list, so
`vulnerable_dependency` uses that mapping family. AI-middleware packages
(litellm / langchain / llama-index / crewai / autogen / openai / anthropic) additionally keep
their ATLAS tag. Every finding stays mapped without forcing SCA findings into the LLM taxonomy.

### CVSS → severity bucket

| CVSS v3 score | GitExpose severity |
|---|---|
| ≥ 9.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| < 4.0 | LOW |
| missing | MEDIUM (default) |

## 6. Exploitability discipline (the CVSS-scoring insight)

> "Stop ranking findings by CVSS. Rank them by whether someone has actually proven they're
> exploitable. A finding nobody has proven exploitable is a hypothesis, not a vulnerability."

This is already GitExpose's philosophy — `--verify` only claims a credential is "live" when it
has proven it. v0.5 extends the same discipline to dependency vulns instead of dumping OSV's
CVSS scores as gospel.

GitExpose does **not** do full code-reachability (out of scope). It uses cheap, high-value
exploitability *context* it already computes:

- **Direct vs. transitive** — a vuln in a direct dependency is far more likely real.
- **Fix available** — actionable now (from OSV `fixed` ranges).
- **Pinned vs. unpinned** — unpinned + vulnerable is worse (reuses `dependency_pinning`).
- **Credential co-presence** — GitExpose's unique angle: it sees the vulnerable dep *and*
  leaked credentials in one scan. A vuln plus a `--verify`-confirmed live credential in the
  same repo is a proven, not hypothetical, exposure.

**Console ordering** uses an exploitability signal
(direct + fix-available + unpinned + cred-co-present) as the **primary** sort key, with CVSS as
a **secondary** key. No overclaiming — consistent with GitExpose's honesty-pass culture.

### VEX, honestly scoped

The CycloneDX `vulnerabilities[].analysis.state` uses only states GitExpose can justify:

- `in_triage` (default) — vuln present, exploitability not proven.
- `exploitable` — **only** when a co-present credential was `--verify`-confirmed live, or it's
  a direct unpinned dependency flagged known-exploited (CISA KEV-style) by OSV.
- We never emit `not_affected` — we cannot prove a negative without reachability analysis.

This keeps the VEX trustworthy rather than compliance theater — the exact failure mode the
insight describes.

## 7. CycloneDX 1.6 AI-BOM

Built with `cyclonedx-python-lib` (pure-Python, guarantees schema conformance, can validate).

- **Metadata:** `tools` = GitExpose + version; `timestamp`; producer.
- **Components:** every parsed dependency, with `purl`, `version`, and `hashes` (from lock-file
  integrity), tagged `direct`/`transitive`. AI tools / middleware / MCP references / detected
  credentials surfaced as component `properties` (the "AI" in AI-BOM is this enrichment; the
  document itself is a complete CycloneDX SBOM).
- **Dependencies:** the resolved dependency graph from the lock file.
- **Vulnerabilities (VEX):** OSV results, each with `affects` → component, `ratings` (CVSS),
  `advisories`, and `analysis.state` per §6.
- **NTIA minimum elements:** producer name, component name/version, unique identifier (PURL),
  component hash, dependency relationships, BOM author (tools), timestamp — all populated.

## 8. Dependencies

| Dependency | Purpose | Notes |
|---|---|---|
| `cyclonedx-python-lib` | CycloneDX 1.6 BOM build + validation | Pure-Python; core dep. The python-magic flakiness concern (system libmagic) does **not** apply. |
| `packageurl-python` | PURL generation | Pulled in by cyclonedx-python-lib; core dep. |
| `tomli>=2.0; python_version < "3.11"` | parse `poetry.lock` (TOML) | stdlib `tomllib` on 3.11+; backport only for the 3.9/3.10 floor. |
| `httpx` (existing) | OSV async client | Reuse — verification engine already uses httpx. No new HTTP dep. |

`yarn.lock` v1 (custom text) and Berry (YAML-ish) are hand-parsed with small regex/line parsers
to avoid adding PyYAML to core deps.

## 9. Error handling

- **OSV unreachable / timeout** → warn, degrade to the curated `KNOWN_BAD_VERSIONS` list, scan
  still succeeds. A network failure is not a scan failure.
- **Lock-file parse error** → skip that file with a warning, continue scanning others.
- **Malformed OSV response entry** → skip that dependency, continue.
- **`cyclonedx` requested but lib missing** → clear message: `pip install gitexpose[bom]`.
- **Exit codes** unchanged: 1 if any findings, 0 if none.

## 10. Testing

- **Parser unit tests** per format — fixtures: `poetry.lock`, `Pipfile.lock`,
  `package-lock.json` (v3), `yarn.lock` (v1 + Berry). PEP 503 / npm name-normalization tests.
- **OSV client** via `respx` / `aioresponses` mocks: querybatch happy path, vuln hydration,
  `--offline` fallback, network-error degradation, `--osv-max` cap.
- **Mapping/ordering** — CVSS→severity bucket; exploitability-ordering (direct + fix-available
  + unpinned + cred-co-present beats higher-CVSS transitive).
- **CycloneDX reporter** — validate output against CycloneDX 1.6 schema (lib validation);
  assert NTIA min-elements present; assert VEX entries present with correct `analysis.state`
  (incl. `exploitable` *only* on verified-cred co-presence).
- **Smoke (`test_smoke_v05`)** — synthetic repo with a recorded-fixture vulnerable dependency →
  `vulnerable_dependency` finding + valid BOM; `--offline` path yields curated-only results.

Run via system Python 3.12 (`/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m
pytest tests/`), not `uv run pytest` (the uv venv lacks dev deps).

## 11. Documentation & release

- Update `README.md` (feature table + Supply-Chain Intelligence section + `--output cyclonedx`
  / `--offline` examples), `docs/COVERAGE.md`, `CHANGELOG.md`.
- Add `docs/v0.5-planning-notes.md` capturing the v0.6 backlog (typosquatting, poisoning checks,
  Shai-Hulud, Go/Cargo).
- Ship gated on manual smoke verification before push, same pattern as v0.2–v0.4.

## 12. v0.6+ backlog (rolled forward)

- Classic typosquatting against popular-package baselines.
- Lock-file poisoning checks (SRI mismatch / ghost deps / off-registry URLs) — data captured in v0.5.
- Shai-Hulud install-time behavioral analysis.
- Go / Cargo ecosystems.
- Capability/scope enumeration for verified credentials.
- Policy engine + tamper-evident audit log.
- AI canary tokens (separate sister project).
