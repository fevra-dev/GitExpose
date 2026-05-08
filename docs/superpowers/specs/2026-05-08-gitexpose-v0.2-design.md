# GitExpose v0.2 — Real-World Hardening Release

**Date:** 2026-05-08
**Status:** Design (pending user review)
**Author:** GitExpose maintainer + Claude (brainstorming session)

---

## 1. Goal

Ship a focused, credible v0.2 release of GitExpose that:

1. Materially expands credential and path detection to mirror what is *actually* leaking in real-world AI/dev codebases.
2. Adds a small, novel supply-chain detection pack covering the March 2026 TeamPCP/LiteLLM incident class.
3. Tags every finding with OWASP LLM Top 10 and MITRE ATLAS metadata for compliance reporting.
4. Reconciles the README with the code that actually exists. Aspirational features move to a clearly-labeled roadmap section.

**Theme:** *Exposure intelligence for AI and dev infrastructure.*

The basis for new patterns is public threat intelligence and real-world leak observations. No external service is queried at scan time.

---

## 2. Scope

### 2.1 In scope

#### 2.1.1 Credential coverage matrix

Pre-existing in v0.1.0 (confirmed by audit during implementation): OpenAI `sk-`, Anthropic `sk-ant-`, Google `AIzaSy`, plus likely AWS `AKIA…` and GitHub PAT `ghp_`.

New in v0.2 — grouped by category. Provider count is the distinct service; pattern count is total individual regexes (some providers have multiple key formats).

**LLM/AI providers (11 providers, 13 patterns):**
- Groq `gsk_[a-zA-Z0-9]{50,}`
- OpenRouter `sk-or-[a-zA-Z0-9_-]{40,}`
- xAI `xai-[a-zA-Z0-9_-]{70,}`
- Cerebras `csk-[a-zA-Z0-9_-]{40,}`
- Hugging Face `hf_[a-zA-Z0-9]{30,}`
- Replicate `r8_[a-zA-Z0-9]{37}`
- Perplexity `pplx-[a-zA-Z0-9]{48}`
- Pinecone `pcsk_[a-zA-Z0-9_-]{30,}` (vector DB / RAG)
- LangSmith `lsv2_pt_[a-zA-Z0-9_-]{40,}` and `ls__[a-zA-Z0-9_-]{40,}` (observability — 2 patterns)
- ElevenLabs (32-char hex, context-bound — only flag when `XI_API_KEY` or `ELEVENLABS_API_KEY` appears anywhere in the same file)
- OpenAI extended forms `sk-proj-[a-zA-Z0-9_-]{40,}` and `sk-svcacct-[a-zA-Z0-9_-]{40,}` (2 patterns)

**Code/cloud/payment infra (3 providers, 5 patterns):**
- Stripe `sk_live_[a-zA-Z0-9]{24,}`, `sk_test_[a-zA-Z0-9]{24,}`, `rk_live_[a-zA-Z0-9]{24,}` (3 patterns)
- GitLab PAT `glpat-[a-zA-Z0-9_-]{20}`
- Docker Hub `dckr_pat_[a-zA-Z0-9_-]{27,}`

**Communication / messaging (5 providers, 5 patterns):**
- Discord bot token `M[\w-]{23,28}\.[\w-]{6,7}\.[\w-]{27,38}`
- Discord webhook `https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+`
- Slack token `xox[abprs]-[\w-]{10,48}`
- Slack webhook `https://hooks\.slack\.com/services/T[\w/]{40,}`
- Telegram bot `\d{8,10}:[\w-]{35}`

**Notifications / SMS (2 providers, 2 patterns):**
- Twilio account SID `AC[a-f0-9]{32}` (cluster post-processor also extracts adjacent auth token if present)
- SendGrid `SG\.[\w-]{22}\.[\w-]{43}`

**Database connection strings (2 providers, 2 patterns):**
- PostgreSQL `postgres(?:ql)?://[^:]+:[^@]+@[^/\s]+`
- MongoDB Atlas `mongodb\+srv://[^:]+:[^@]+@[^/\s]+`

**Total new in v0.2: 23 providers, 27 individual regex patterns. Combined with v0.1.0: ~28 providers covered.**

#### 2.1.2 Novel detection mechanisms

**Multi-provider-key file flagging.** Files matching `OAI_CONFIG_LIST`, `**/litellm_config.{yaml,yml}`, `.continue/agents/*.yaml`, or any path that contains ≥2 distinct provider patterns are emitted as a `multi_provider_credential_file` finding with severity boosted to CRITICAL. The framing is blast-radius — one file compromises N providers at once.

**Paired-secret cluster detection.** When ≥2 distinct secret patterns co-occur in the same file, scanner emits a `credential_cluster` finding (severity CRITICAL) summarizing all matched secret types alongside the individual matches. Enables blast-radius reasoning across files. The cluster finding includes a `member_findings` field with references to the individual matches.

**Non-goal:** these mechanisms do *not* replace individual findings. The original per-secret findings are still emitted unchanged. Cluster and multi-provider findings are added alongside them so consumers can filter at whichever granularity they need.

#### 2.1.3 Empirical AI-tool config paths

Add to `paths_extended.py` and `llm_exposure_scanner.AI_TOOL_CONFIGS`:

- `.continue/agents/*.yaml`, `.continue/config.yaml`, `.continue/**/*.yaml`
- `claude/.credentials.json`, `claude/credentials.json`
- `**/LiteLLM*config*.{yaml,yml,md}`, `**/litellm*config*`, `**/litellm_config.{yaml,yml}`
- `**/@config.json.md`
- `**/mcp.json`, `.cursor/mcp.json`, `.continue/mcp.json`
- `**/bin/Debug/**/appsettings*.json`, `**/bin/Release/**/appsettings*.json`, `**/obj/**/appsettings*.json`
- `**/drizzle.config.ts`, `drizzle.config.ts`
- `**/*.env.*.example`, `**/.env.*.example`, `**/*.env.bak`, `**/.env.*.bak`, `**/.env.backup`, `**/.env.old`
- `**/agents.yaml`, `**/tasks.yaml`, `**/crew.yaml` (CrewAI)
- `OAI_CONFIG_LIST` (AutoGen — bare filename, no extension)
- `**/firebase-config.{js,ts}`, `**/firebase*.config.{js,ts}`

#### 2.1.4 TeamPCP supply chain pack

Three new modules under `gitexpose/advanced/`, each one focused:

- **`dependency_pinning.py`** — `DependencyPinningScanner` consumes `requirements.txt`, `pyproject.toml`, `package.json`. Emits findings (severity HIGH, `attack_class="LLM05"`) for unpinned AI middleware: `litellm`, `langchain`, `langchain-core`, `llama-index`, `autogen`, `crewai`, `openai`, `anthropic`. No network calls.

- **`known_bad_versions.py`** — exposes `KNOWN_BAD_VERSIONS: dict[str, set[str]]` data structure plus `scan_requirements(text) -> list[Finding]` function. Initial corpus:
  - `litellm` → `{"1.82.7", "1.82.8"}`
  - `telnyx` → `{"4.87.1", "4.87.2"}`
  - `xinference` → `{"2.6.0", "2.6.1", "2.6.2"}`
  - `gptplus`, `claudeai-eng`, `hermes-px` → any version (these packages are entirely malicious)
  - Severity CRITICAL.

- **`slopsquatting.py`** — exposes `KNOWN_SLOPSQUATS: set[str]` plus `check(name) -> bool`. Curated initial corpus (target: 25-30 names — exact list finalized during implementation by cross-referencing the USENIX 2025 study and PyPI typosquat registries):
  - Confirmed real-world: `huggingface-cli` (30K downloads from hallucinated install command)
  - High-risk variants: `openai-sdk`, `anthropic-sdk`, `langchai`, `langchian`, `anthropicc`, `openai-python`, `gptplus`, `claudeai-eng`, `hermes-px`, `deepseek-sdk`, `deepseek-api`, `deepseeksdk`, `deepseekai`, `huggingface-py`, `langchain-py`
  - Each match emits CRITICAL with `attack_class="LLM05"`, `atlas_technique="AML.T0019"`, and reference to slopsquatting research in evidence text.
  - The corpus is committed to source as code-as-data; new entries are added by PR.

#### 2.1.5 Supply-chain Python regex patterns

Added to a new `gitexpose/advanced/supply_chain_patterns.py`:

- `pth_persistence` — `.pth` file in `site-packages` containing `exec(`, `eval(`, or `base64.b64decode`. Severity CRITICAL.
- `ai_c2_beacon` — instructional text matching "on every (run|startup|invocation): … https://" or "poll … commands from https://" (high-confidence subset only). Severity CRITICAL, `attack_class="LLM08"`, `atlas_technique="AML.TA0015"`.
- `kubernetes_exfiltration` — `kubectl get secrets`, `/var/run/secrets/kubernetes.io/serviceaccount`, `KUBERNETES_SERVICE_HOST` aggregation. Severity CRITICAL, `attack_class="LLM06"`.

WAV/audio steganography, browser-agent misuse, multi-agent injection patterns are deferred — too low-confidence to ship at CRITICAL severity in v0.2.

#### 2.1.6 Reporting

Extend `models.py` `Finding` (or whichever class is canonical) with two optional fields:

- `attack_class: str | None` — OWASP LLM Top 10 ID (e.g., `"LLM05"`, `"LLM06"`, `"LLM08"`)
- `atlas_technique: str | None` — MITRE ATLAS technique ID (e.g., `"AML.T0056"`, `"AML.TA0015"`)

Reporter changes:

- **JSON** — emit both fields per finding. Backwards-compatible (consumers ignore unknown keys).
- **SARIF** — add a `taxonomies` block referencing MITRE ATLAS as the taxonomy, per-result `taxa` reference resolves to the technique ID. Validates against SARIF 2.1.0 schema.
- **HTML** — render two badges per finding (OWASP LLM ID and ATLAS technique ID), each linked to canonical reference URLs.
- **CSV / Console** — append two new columns/lines.

#### 2.1.7 CLI surface

- `gitexpose supply-chain <path>` — new subcommand. Walks the path, runs the three TeamPCP-pack scanners and supply-chain regex patterns. Pure-local, no network.
- `gitexpose scan ... --full-audit` — existing flag now also runs the supply-chain scan automatically.

No breaking changes to existing commands.

#### 2.1.8 Data layout

- `gitexpose/data/credential_patterns.json` — bundled static corpus, single source of truth for the 22-provider matrix. Schema includes `provider`, `pattern`, `severity`, `verified_paths[]`, `attack_class`, `atlas_technique`. Loaded at import time and merged into runtime pattern lists.
- The data file format is designed to support a future swap-in of an upstream feed if/when one becomes available. Not in scope for v0.2.

#### 2.1.9 Documentation

- **`docs/COVERAGE.md`** — new file. Provider parity matrix listing all 22 providers with categories. Marketable artifact.
- **`README.md` honesty pass:**
  - Adopt *"exposure intelligence for AI and dev infrastructure"* framing in tagline/description.
  - Trim claims for unimplemented features: ML detection engine, runtime monitoring proxy, plugin architecture, web dashboard, package verification CLI, "65+ attacks", "triple-layer defense" (only Layer 1 actually exists).
  - Move aspirational features to a `## Roadmap (not yet implemented)` section.
  - Update detection coverage table with accurate counts.
  - Fix any other claims that don't reflect shipped code.
- **`docs/README_ADVANCED.md`** — same honesty pass as README.

#### 2.1.10 Tests

- ~40-50 unit tests covering positive and negative cases for each new pattern.
- 4 fixture-driven integration tests for supply-chain scanner:
  - `tests/fixtures/requirements_clean.txt` — pinned, safe AI deps → 0 findings
  - `tests/fixtures/requirements_teampcp.txt` — known-bad versions → 3 CRITICAL findings
  - `tests/fixtures/requirements_unpinned.txt` — unpinned middleware → 3 HIGH findings
  - `tests/fixtures/requirements_slopsquat.txt` — hallucinated names → 3 CRITICAL findings
- Reporter contract tests: JSON keys, SARIF schema validation against 2.1.0 spec, HTML badge presence, CSV/console column presence.
- End-to-end smoke test against `tests/fixtures/synthetic_repo/` with planted secrets and clean control file.
- Regression guard: existing test suite must pass.

### 2.2 Out of scope (deferred to v0.3+)

- Live external API enrichment for severity weighting
- `update-signatures` CLI command (no validated upstream feed currently)
- Tier 3 providers: Helicone, Portkey, Voyage, GitHub Models, Cohere, Modal, Runpod
- Full MITRE ATLAS coverage map document (we ship metadata only)
- WAV/audio steganography detection
- Browser-agent misuse, multi-agent injection patterns
- ML detection engine, runtime monitoring proxy, plugin architecture, web dashboard, REST API
- Performance benchmarking for the new patterns
- Live integration with GitHub Code Scanning

---

## 3. Components & file layout

### 3.1 Modified files (existing)

- `gitexpose/signatures.py` — credential prefix regexes; new patterns loaded from `data/credential_patterns.json` rather than hardcoded.
- `gitexpose/paths_extended.py` — append empirical paths from §2.1.3.
- `gitexpose/advanced/llm_exposure_scanner.py` — extend `AI_TOOL_CONFIGS` with new categories: `continue_dev`, `claude_credentials`, `litellm_proxy`, `mcp_configs`, `net_build_output`, `drizzle_orm`, `crewai_configs`, `autogen_configs`, `firebase_config`. Each carries severity, recommendation, `attack_class`, `atlas_technique`.
- `gitexpose/models.py` — extend `Finding` (or `ScanResult`) with `attack_class: str | None` and `atlas_technique: str | None`.
- `gitexpose/reporters/json.py` — emit new fields.
- `gitexpose/reporters/sarif.py` (or wherever SARIF lives) — add taxonomy block, per-result `taxa` references.
- `gitexpose/reporters/html.py` — render badges.
- `gitexpose/reporters/csv.py` — new columns.
- `gitexpose/reporters/console.py` — surface new fields.
- `gitexpose/cli.py` — register `supply-chain` subcommand; wire `--full-audit` to call it.
- `gitexpose/scanner.py` (if needed) — add multi-provider-key file detection and paired-secret cluster post-processing pass over findings.
- `README.md`, `docs/README_ADVANCED.md` — honesty pass.

### 3.2 New files

**Source:**
- `gitexpose/data/credential_patterns.json` — 22-provider matrix with schema described in §2.1.8.
- `gitexpose/data/__init__.py` (if needed for package discovery).
- `gitexpose/advanced/dependency_pinning.py` — `DependencyPinningScanner` class.
- `gitexpose/advanced/known_bad_versions.py` — `KNOWN_BAD_VERSIONS` constant + `scan_requirements()`.
- `gitexpose/advanced/slopsquatting.py` — `KNOWN_SLOPSQUATS` constant + `check()`.
- `gitexpose/advanced/supply_chain_patterns.py` — regex patterns for `pth_persistence`, `ai_c2_beacon`, `kubernetes_exfiltration`.
- `gitexpose/advanced/credential_cluster.py` — post-processing logic for multi-provider-key file flagging and paired-secret cluster detection. Operates on the list of `Finding` objects returned by the scanner.

**Documentation:**
- `docs/COVERAGE.md`
- `docs/superpowers/specs/2026-05-08-gitexpose-v0.2-design.md` (this document)

**Tests:**
- `tests/test_credential_patterns.py` — covers all 22 patterns
- `tests/test_empirical_paths.py`
- `tests/test_dependency_pinning.py`
- `tests/test_known_bad_versions.py`
- `tests/test_slopsquatting.py`
- `tests/test_supply_chain_patterns.py`
- `tests/test_credential_cluster.py` — multi-provider + paired-secret logic
- `tests/test_reporters_v02.py` — reporter contract tests for new fields
- `tests/test_supply_chain_cli.py` — end-to-end smoke
- `tests/fixtures/requirements_clean.txt`
- `tests/fixtures/requirements_teampcp.txt`
- `tests/fixtures/requirements_unpinned.txt`
- `tests/fixtures/requirements_slopsquat.txt`
- `tests/fixtures/synthetic_repo/` — directory tree with planted findings

### 3.3 Boundary rationale

- Three small files for the supply-chain pack (`dependency_pinning`, `known_bad_versions`, `slopsquatting`) instead of one merged file: different inputs, different update cadences, different test surfaces. Combined ~300 lines.
- `credential_patterns.json` as data-not-code: easier to extend, easier to diff, sets up future external-feed swap.
- `credential_cluster.py` as a separate post-processor (not embedded in scanner): runs over already-collected findings, easier to test in isolation, easier to disable if it produces noise.
- No new top-level subpackage. Everything lives under `gitexpose/` or `gitexpose/advanced/`.

---

## 4. Data flow & integration

### 4.1 Existing flow

```
CLI (cli.py)
  → scanner.py
  → advanced/* modules
  → models.py (Finding / ScanResult)
  → reporters/*
```

### 4.2 v0.2 integration points

**(1) Secret prefix detection — passive, automatic**

`signatures.py` now loads `data/credential_patterns.json` at import time and merges into existing pattern lists. The existing scanner engine picks up matches automatically. Each match is a `Finding` with severity, `attack_class="LLM06"`, and (where applicable) `atlas_technique`.

**(2) Path detection — extends existing path-based scanning**

New paths land in `paths_extended.py` and `llm_exposure_scanner.AI_TOOL_CONFIGS`. The existing path matcher iterates them. ATLAS metadata: each category dict gains `attack_class` and `atlas_technique` keys; the scanner copies those onto emitted Findings.

**(3) Supply-chain scanning — new active flow**

```
gitexpose supply-chain <path>
  → walk path looking for requirements.txt / pyproject.toml / package.json
  → for each dependency file:
        DependencyPinningScanner.scan(text)
        scan_requirements(text)              # known-bad versions
        slopsquatting.check(name) per dep
  → walk path looking for in-scope text files (extensions: .py, .yaml, .yml,
    .json, .toml, .md, .txt, .cfg, .ini, .sh, .pth, Dockerfile)
  → for each text file:
        supply_chain_patterns.scan(text)     # pth / C2 / k8s
  → emit Findings with severity + attack_class + atlas_technique
```

Binary files, images, lock files, and the `.git/` directory are skipped by default. Files larger than 1 MB are skipped (configurable in implementation).

**(4) Credential cluster post-processing — new pass**

After the scanner produces a flat list of Findings, `credential_cluster.process(findings)` runs:

```
group findings by (file_path, finding_kind == "secret")
for each group with ≥2 distinct provider matches:
    emit credential_cluster Finding (CRITICAL)
    members[] = original findings
for each file matching multi-provider-key path patterns AND containing ≥2 provider patterns:
    emit multi_provider_credential_file Finding (CRITICAL)
```

The original individual findings remain in the result list. The cluster/multi-provider findings are added alongside them. Reporters surface both.

**(5) Reporter changes**

- JSON: include `attack_class` and `atlas_technique` per finding.
- SARIF: add `taxonomies` block at run level referencing MITRE ATLAS; per-result `taxa` reference to technique ID.
- HTML: render two badges per finding (OWASP LLM and ATLAS), linked to canonical references.
- CSV / Console: two new columns/fields.

### 4.3 Error handling

- Missing dependency file → silent skip (project may not be Python/Node).
- Malformed `pyproject.toml` → log warning, fall back to regex on raw text.
- Malformed `package.json` → same fall-back.
- Static corpus files (`credential_patterns.json`, `KNOWN_BAD_VERSIONS`, `KNOWN_SLOPSQUATS`) cannot fail at runtime. The loader validates schema at import time and raises `ImportError` with a clear message if the JSON is missing or malformed — a packaged release that ships a broken corpus must fail loudly. One unit test asserts schema validity to catch this in CI before release.
- New regex patterns inherit existing scanner error behavior; no new try/except.

### 4.4 Trace example

Scanning a repo with `requirements.txt` containing `litellm==1.82.7`:

1. CLI: `gitexpose supply-chain ./repo`
2. Walk finds `./repo/requirements.txt`.
3. `DependencyPinningScanner` — no finding (it is pinned, just to a malicious version).
4. `scan_requirements` — matches `litellm==1.82.7` → `Finding(severity=CRITICAL, title="Known-malicious AI package version pinned", attack_class="LLM05", atlas_technique="AML.T0019", evidence="litellm==1.82.7 — known compromised version, March 2026 supply chain incident")`.
5. JSON reporter writes finding with both ATLAS/OWASP fields.
6. SARIF reporter emits result with taxonomies reference.

---

## 5. Testing strategy

### 5.1 Layers

**Unit tests — regex correctness**

Two cases per pattern minimum: positive match against realistic key string; negative against prose collision (e.g., `gsk_was_a_thing`, `sk-or-not`).

**Fixture-driven integration tests**

Four `requirements.txt` fixtures: clean, teampcp, unpinned, slopsquat. Each test asserts count, severity distribution, ATLAS metadata population, and evidence content.

**Reporter contract tests**

Build a single fixture `Finding` set covering all new categories, render via each reporter, and assert:

- JSON: presence of `attack_class` and `atlas_technique` keys per finding.
- SARIF: validates against the OASIS-published SARIF 2.1.0 JSON schema (vendored locally under `tests/fixtures/sarif-schema-2.1.0.json` to keep tests offline-only); `taxonomies` block present; per-result `taxa` resolves; technique ID strings appear.
- HTML: rendered output contains the OWASP LLM ID and ATLAS technique ID strings as badge text.
- CSV: new columns present in header and data rows.
- Console: ATLAS technique ID appears in finding output.

**End-to-end smoke**

`tests/fixtures/synthetic_repo/` with planted secrets across multiple file types. Run `gitexpose scan --full-audit` and assert: every planted finding caught, no false positives on the clean control file, cluster detection fires on the file containing ≥2 secret types, multi-provider detection fires on the planted `OAI_CONFIG_LIST`.

**Regression guard**

The existing test suite must continue to pass. A small spot-check fixture (clean Python project with no AI deps) must produce the same findings as v0.1.0 — catches accidental over-broad regex changes.

### 5.2 Manual verification before tagging

- `gitexpose --help` — `supply-chain` subcommand visible.
- Scan against a real, known-clean repo (one of the user's own non-AI projects) and confirm zero false positives on the new patterns.
- Skim rendered HTML report — ATLAS/OWASP badges look right and link to correct references.

### 5.3 Out of scope for v0.2 testing

- No live network tests.
- No fuzz testing of regexes.
- No performance benchmarking (patterns add no hot-path work).
- No live GitHub Code Scanning integration test.

### 5.4 Realistic test count

~40-50 new test cases. Total runtime well under 10 seconds.

---

## 6. Success criteria

- All 22 credential patterns have positive and negative test cases passing.
- All 4 supply-chain fixtures produce expected findings.
- Reporter contract tests pass for JSON, SARIF, HTML, CSV, and Console.
- End-to-end smoke catches all planted findings on synthetic repo with no false positives on control files.
- Existing test suite passes (regression guard).
- README claims align with shipped code (verified by reading both).
- `docs/COVERAGE.md` exists and accurately lists all 22 providers.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| New regex patterns produce false positives in real repos | Length floors and prefix specificity in each pattern; manual verification against real clean repo before tagging |
| ElevenLabs 32-hex pattern collides with other 32-char hex tokens | Bind to context: only match when adjacent to `XI_API_KEY` / `ELEVENLABS_API_KEY` in same file |
| Stripe `sk_test_` collides with similar prefixes from other providers (e.g., Clerk) | Length floor + literal `live`/`test` distinguishers; reduce confidence if not adjacent to known Stripe context |
| README honesty pass perceived as feature regression | Frame as version-appropriate trim with explicit roadmap; preserve all current functionality |
| Cluster detection produces overwhelming noise on legitimate config files | Cluster only emits when ≥2 *distinct* provider patterns match; multi-provider emits only on whitelisted aggregator paths |
| `credential_patterns.json` schema breaks if extended carelessly | Loader validates schema at import time; one explicit test asserts schema validity |
| Effort overruns 1.5-week estimate | Stop-loss: defer Tier 2 patterns to v0.2.1 patch if Tier 1 + supply-chain pack consumes the full window; the matrix doc and ATLAS metadata are the differentiators that must ship |

---

## 8. Effort estimate

~1.5 weeks of focused work, distributed roughly:

- Credential audit + Tier 1 patterns + tests: 2-3 days
- Tier 2 patterns + cluster detection + tests: 2 days
- Empirical paths + AI_TOOL_CONFIGS expansion + tests: 1 day
- TeamPCP supply-chain pack + tests: 2 days
- ATLAS/OWASP metadata + reporter changes + tests: 1.5 days
- README/docs honesty pass + COVERAGE.md: 1 day
- End-to-end smoke + manual verification + release prep: 1 day

This is a focused-feature release, not a substantial release. Holding the line on the §2.2 deferred items is critical to shipping.

---

## 9. Open questions resolved during brainstorm

- *Live external API enrichment* — deferred. Privacy concern (leaking scan-target paths to a third party) and reliability concern (network failure modes) outweigh the dynamic-severity benefit.
- *MITRE ATLAS coverage map document* — deferred to v0.3. The metadata fields ship in v0.2, the marketing artifact does not.
- *Paired-secret cluster as separate finding vs. severity boost* — separate finding. Easier to filter, easier to render, gives better blast-radius framing.
- *Credential pattern data location* — single `gitexpose/data/credential_patterns.json` vs. multiple files. Single file. Simpler loader, simpler diff.

---

## 10. Next step

Implementation plan (writing-plans skill) to break the above into ordered, atomic tasks.
