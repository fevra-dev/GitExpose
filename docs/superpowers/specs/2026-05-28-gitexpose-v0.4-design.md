# GitExpose v0.4 — Design Spec ("Detection Depth")

> Status: brainstorm-approved, pending implementation plan
> Date: 2026-05-28
> Prior release: v0.3.0 (shipped 2026-05-28)
> Pre-brainstorm notes: [`docs/v0.4-planning-notes.md`](../../v0.4-planning-notes.md)
> Implementation plan: TBD (to be produced by `superpowers:writing-plans`)

## 1. Goal

Ship v0.4 with **git-history secret scanning** as the headline: find credentials that were committed and later removed but still live in git history (and often still valid) — the single biggest detection-surface gap in GitExpose today. Make it cutting-edge by **chaining it into the v0.3 `--verify` engine**: a secret deleted 80 commits ago can be reported as *confirmed live right now*.

Secondary goal: ship a net-new **AI-supply-chain signature pack** (4 content-analysis detection classes) that finds new attack classes in the working tree, plus close the AWS-verification gap.

North star (user's framing): practical, cutting-edge, finds new gaps in supply-chain and secrets. v0.4 is a **detection-depth + new-attack-class** release, not a compliance release.

## 2. Scope

### 2.1 In scope

1. **`gitexpose git-history <path>`** (headline) — diff-based git-history secret scanning across all reachable commits; composes with `--verify`.
2. **AI-supply-chain signature pack** (4 net-new classes, working-tree only):
   - LangGrinch `lc` credential pattern (CVE-2025-68664) → `credential_patterns_v02.json`
   - Polyglot / extension-content mismatch detection → `skill_security.py`
   - Skill/prompt-injection instruction patterns → `skill_security.py`
   - Malicious-content scanning inside multi-agent configs → `skill_security.py`
3. **AWS access+secret pairing** — so `aws_access_key` findings actually verify live.
4. Version bump to 0.4.0, CHANGELOG, docs, tests.

### 2.2 Surface boundary (deliberate)

- **`git-history` scans credential SECRETS in history** (runs `SecretExtractor` over historical diffs).
- **The signature pack does content analysis on the WORKING TREE** (via `supply-chain` / `local_fs_scanner`).
- The 4 content-analysis detectors are **NOT** run over historical diffs in v0.4. Rationale: a leaked secret stays exploitable after removal (history matters), but a malicious instruction file removed long ago is not a live threat; running 4 content detectors over every historical file version is a combinatorial blowup with high FP noise and little value. Secrets→history, content→working-tree.

### 2.3 Out of scope (→ v0.5+)

- AI-BOM (`--format aibom`) — deferred; stronger after deep-scan produces more to inventory
- Policy engine + tamper-evident audit log
- Unreachable/dangling-blob walk (force-pushed-away secrets; TruffleHog `--batch-all-objects` parity)
- Other provider verifiers (Discord bot/webhook, Telegram, Twilio, SendGrid, Stripe)
- `--verify` on the web-scan (`cli.py:main`) path
- Capability/scope enumeration (AWS IAM perms, GitHub PAT scopes, OpenAI org)
- AI canary tokens (separate sister project)
- Running the signature pack over git history

## 3. Architecture

### 3.1 Module layout

```
gitexpose/git_history/                 # NEW — headline
├── __init__.py        # public API: scan_history(repo_path, *, since=None, max_commits=None) -> list[dict]
├── scanner.py         # orchestrator: spawn git, drive parser, run SecretExtractor, dedup, attach metadata
└── diff_parser.py     # streaming state-machine parser for `git log -p` output

gitexpose/advanced/skill_security.py   # NEW — signature pack (3 content detectors)
  - detect_polyglot(path) -> list[dict]
  - scan_skill_injection(path, content) -> list[dict]
  - scan_agent_config_content(path, content) -> list[dict]
  - module constants: SKILL_FILE_GLOBS, INJECTION_PATTERNS, AGENT_CONFIG_GLOBS
```

### 3.2 Modified files

- `gitexpose/cli_advanced.py` — add the `git-history` subcommand; factor the `--verify*` Click options into a shared decorator reused by `supply-chain` and `git-history`
- `gitexpose/data/credential_patterns_v02.json` — add the LangGrinch `lc` pattern
- `gitexpose/advanced/local_fs_scanner.py` — call `skill_security` detectors over matching working-tree files during a `supply-chain` scan
- `gitexpose/verification/engine.py` — add `pair_aws_credentials(findings)` pre-step before `verify_secrets`
- `gitexpose/__init__.py`, `pyproject.toml`, `setup.py` — version 0.4.0; add `python-magic` as an OPTIONAL extra (not a hard runtime dep)
- `docs/COVERAGE.md`, `README.md`, `CHANGELOG.md` — coverage + usage + release notes; new `docs/` usage section for `git-history`

### 3.3 Decomposition rationale

- `git_history/` is its own package: distinct perf profile (streams a subprocess), distinct output shape (commit metadata), and a non-trivial parser that deserves isolation + focused unit tests.
- `diff_parser.py` separated from `scanner.py`: the parser is the riskiest code and is purely a function of stdin text → testable on canned `git log -p` output without spawning git.
- `skill_security.py` groups the 3 content detectors: they're all "is this AI-skill/agent file malicious?" analysis, share the injection-pattern constants, and run together over the working tree.
- AWS pairing lives in the engine (not in `aws.py`): it's a finding-list transformation, and `aws.verify` already accepts the `access:secret` form unchanged.

## 4. git-history scanner

### 4.1 Mechanism

- Spawn (streamed stdout): `git -C <path> log -p --all --reverse -U0 --no-color --pretty=format:"\x01%H\x00%an\x00%aI"`
  - `--all` → every commit reachable from any branch/ref
  - `--reverse` → oldest-first, so the FIRST sighting of a secret is its earliest-introducing commit (correct dedup attribution)
  - `-U0` → zero context lines (only actual changed lines)
  - `--no-color` → clean parsing
  - sentinel `\x01%H\x00%an\x00%aI` → unambiguous per-commit SHA / author / ISO-date (NUL-separated, won't collide with diff content)
- Optional bounds: `--since <date>` and `--max-commits N` pass through to `git log`.

### 4.2 Parser (`diff_parser.py`)

Streaming state machine tracking `(current_commit_meta, current_file)`:
- A `\x01`-prefixed line → parse SHA/author/date, update current commit.
- A `diff --git` / `+++ b/<path>` line → set current file (strip the `b/` prefix; handle `/dev/null` for deletions).
- A `Binary files … differ` line → skip the hunk.
- A `+`-prefixed line that is NOT the `+++` header → an added content line; accumulate per (commit, file).
- Decode with `errors="replace"` to survive non-UTF8 blobs.

Yields `(commit_meta, file_path, added_text)` tuples to the scanner.

### 4.3 Detection + dedup + metadata

- For each `(commit, file, added_text)`, run `SecretExtractor.extract(added_text, source=file_path)` — reuses the full 29-provider + context-bound corpus; no new pattern logic.
- Global `seen: set[str]` keyed by raw `value_full`. First occurrence (oldest commit) is kept; later survivals skipped → each secret reported once, attributed to its introducing commit.
- Each kept finding gains: `commit` (full SHA), `commit_short`, `author`, `commit_date` (ISO), `source` (path at that commit). Existing `type`/`value`/`value_full`/`context`/`attack_class`/`atlas_technique`/`severity`/`verification_status`/`verification_detail` carry through.

### 4.4 `--verify` composition

After dedup, if `--verify` is set: run `pair_aws_credentials(findings)` then `verify_secrets(findings, concurrency=…, timeout=…)` — the same v0.3 engine. Historical findings carry `type`+`value_full`, so verification works unchanged. Result: a historical secret gets `verified`/`dead`/`error`.

### 4.5 Bounds / robustness

- Streaming keeps memory flat (only the dedup set grows).
- Non-git path → exit with a clear error (`not a git repository`).
- Empty/clean history → "✅ No historical secrets found.", exit 0.
- Merge-commit duplication and binary hunks handled/skipped by the parser.

## 5. Finding shape

Reuses the v0.3 secret-dict (so `--verify` + reporting work unchanged), plus history metadata:

```python
{
  "type": "openai_api_key",
  "value": "sk-…aB3z",            # masked
  "value_full": "sk-…",           # raw (used by verifier; redacted in logs)
  "source": "config/old_settings.py",
  "commit": "a1b2c3d4…", "commit_short": "a1b2c3d",
  "author": "Jane Dev", "commit_date": "2025-11-04T12:30:00-05:00",
  "verification_status": "skipped",      # verified/dead/error when --verify
  "verification_detail": None,
  "attack_class": "LLM06", "atlas_technique": "AML.T0019",
  "severity": "CRITICAL",
}
```

## 6. CLI surface

New subcommand on the `cli_advanced.cli` group:

```
gitexpose git-history <path> [options]
  -o, --output {console,json}      default: console
  --out-file PATH                  write to file instead of stdout
  --since DATE                     only commits after DATE (passthrough to git log)
  --max-commits N                  cap commits scanned
  --verify                         verify discovered historical secrets (opt-in)
  --verify-concurrency N           default 5
  --verify-timeout SECONDS         default 5.0
  --no-verify-banner               suppress the consent banner
```

The `--verify*` flags are factored into a shared Click decorator (`add_verify_args` equivalent) reused by both `supply-chain` and `git-history`, eliminating duplication.

## 7. Output

**Console:**
```
🔍 3 historical secret(s) in . (across all branches):
  [CRITICAL] openai_api_key   (config/old_settings.py @ a1b2c3d, Jane Dev, 2025-11-04)
     ✓ VERIFIED (credential is LIVE)        # only when --verify
  [CRITICAL] aws_access_key   (deploy.sh @ f9e8d7c, Bob, 2025-09-12)
     ✗ DEAD (credential rejected by provider)
  [HIGH] postgres_url         (.env.bak @ 7c6b5a4, Jane Dev, 2025-08-01)
     – unverifiable (no verifier for this type)
```

- **JSON** (`-o json`): list of finding dicts with all fields above.
- **Exit code:** `1` if any findings, `0` if clean (matches `supply-chain`).
- **Consent banner:** `--verify` prints the v0.3 stderr banner (suppressible with `--no-verify-banner`).

## 8. AI-supply-chain signature pack

All run over the working tree via `local_fs_scanner` during a `supply-chain` scan.

### 8.1 LangGrinch `lc` credential pattern (CVE-2025-68664)

- A new entry in `credential_patterns_v02.json` for the LangChain `lc-`-prefixed key tied to the LangGrinch advisory.
- **Open item:** the exact regex + length bounds are finalized during implementation from the research source (`RESEARCH/gitexpose-skill-poison-plan.md`, rule SK-YARA-017) / the CVE advisory; confirm it does not overlap the existing `lsv2_pt_` / `ls__` LangSmith patterns. If the format cannot be confirmed, ship a documented best-effort pattern or defer this single item (does not block the rest of v0.4).
- Severity CRITICAL, `attack_class: LLM03`, ATLAS technique on the entry.

### 8.2 Polyglot / extension-content mismatch — `detect_polyglot(path)`

- Reads magic bytes via `python-magic` (libmagic) and flags a text-extension file (`.md`, `.yaml`, `.yml`, `.json`, `.txt`, `.py`) whose actual content is a binary/archive/executable (ELF, PE/`MZ`, ZIP, PDF, …) — a disguised payload.
- Severity HIGH.
- **Graceful degradation:** if libmagic is unavailable, the detector logs a one-line skip and returns `[]` — never crashes a scan. `python-magic` is an OPTIONAL extra, not a hard runtime dependency.

### 8.3 Skill/prompt-injection instruction patterns — `scan_skill_injection(path, content)`

- Scans **instruction-class files only** (scoped allowlist: skill `.md`, `CLAUDE.md`/`AGENTS.md`/`GEMINI.md`, `.continue/` agent files, `.cursor/rules`).
- High-signal directives: "ignore/disregard previous/prior instructions", tool-use hijack phrasing, data-exfil instructions (`POST … to http…`, `send … to <url>`), large base64 blobs in instruction context.
- Composes with the existing `invisible_unicode_detector` (does NOT duplicate it).
- Severity HIGH, `attack_class: LLM01`.
- **FP control:** conservative high-precision patterns + the file-scope allowlist; errs toward precision over recall (this is the highest-FP-risk detector).

### 8.4 Malicious content inside multi-agent configs — `scan_agent_config_content(path, content)`

- v0.2 detects the *presence* of CrewAI (`agents.yaml`/`tasks.yaml`/`crew.yaml`), AutoGen (`OAI_CONFIG_LIST`), litellm configs; this scans their *contents*.
- Detects embedded injection payloads (reuses §8.3 patterns) and suspicious tool/command definitions (`exec`/`eval`/`curl`/`wget` to external hosts in agent task defs). Composes with v0.2's `ai_c2_beacon`.
- Severity HIGH/CRITICAL.

## 9. AWS access+secret pairing

- **Problem:** `SecretExtractor` emits `aws_access_key` (`AKIA…`) and `aws_secret_key` (40-char) as separate findings; the v0.3 AWS verifier needs `ACCESS:SECRET` → currently `ERROR (expected access:secret pair)`.
- **Solution:** `pair_aws_credentials(findings)` in `gitexpose/verification/engine.py`, run before `verify_secrets`. For each `aws_access_key` finding, find an `aws_secret_key` finding with the same `source`; if found, set the access-key finding's verify-input to `<access>:<secret>` and pass to the unchanged `aws.verify`. No same-source secret → stays `ERROR ("no paired secret in source")`.
- Benefits both `supply-chain` and `git-history` (both emit these dicts with `source`).
- **Limitation (documented):** multiple keypairs in one file pair best-effort by same-source; cross-commit pairs in history won't pair.

## 10. Testing strategy

All network mocked (`respx`); no live calls in CI. System Python 3.12 for the suite (uv venv lacks dev deps).

- **`git_history`** — pytest fixture builds a temp git repo (commit a secret, remove it next commit, add a branch); asserts: secret found with correct SHA/author/date; dedup attributes to earliest commit (`--reverse`); non-git path errors cleanly; empty history → no findings; `--verify` composition (mocked). ~8–10 tests.
- **`diff_parser`** — unit tests on canned `git log -p` output: sentinel commit lines, `+++` headers, `-U0` added lines, binary-hunk skip, non-UTF8 `errors="replace"`, `/dev/null` deletions. ~5–6 tests.
- **`skill_security`** — polyglot (craft `.md` with PE/ELF/ZIP magic bytes; libmagic-missing graceful-skip test); injection (positive skill file + **negative** benign file → no FP); agent-config content (config with `exec`/`curl` payload + negative benign config). ~10 tests.
- **lc pattern** — match/non-match in the existing corpus test (`test_credential_patterns_v02.py` or `test_tier3_patterns.py` sibling).
- **AWS pairing** — same-source access+secret → paired → VERIFIED (mocked); unpaired → ERROR; different-source → not paired. ~3 tests.
- **CLI** — `CliRunner`: `git-history --help` shows the flags; run against the fixture → JSON with commit metadata; exit codes 0/1.
- **Target:** ~30+ new tests; suite 251 → ~285+.

## 11. Effort & risk

| Component | Hours |
|---|---|
| `git_history` module (scanner + diff_parser + tests) | 7 |
| `skill_security` (3 detectors + tests) | 6 |
| LangGrinch `lc` pattern | 0.5 |
| AWS pairing + tests | 2 |
| `git-history` CLI + output + verify wiring | 2 |
| Docs (COVERAGE, git-history usage, README), version bump, CHANGELOG | 2.5 |
| **Total** | **~20h** |

### Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| diff-parser edge cases (renames, merges, binary, huge/non-UTF8 diffs) | Medium | `-U0` + `--no-color` + sentinel format + binary skip + `errors="replace"`; the parser is pure-function over text → thorough canned-output unit tests |
| prompt-injection false positives | Medium | file-scope allowlist + high-precision patterns; err toward precision; negative tests required |
| libmagic unavailable | Medium | graceful skip returning `[]`; ship `python-magic` as optional extra, not hard dep |
| large-repo perf | Medium | streaming (flat memory) + `--max-commits`/`--since` bounds |
| LangGrinch `lc` format uncertainty | Medium | confirm from research doc/CVE during impl (time-boxed); if unconfirmable, ship best-effort or defer just this one item |
| AWS pairing ambiguity (multiple keypairs/file) | Low | best-effort same-source pairing; documented limitation |

## 12. Acceptance criteria

1. `gitexpose git-history <fixture-repo>` finds a secret that was committed-then-removed, with correct commit SHA/author/date, and dedups it to the introducing commit.
2. `gitexpose git-history <fixture-repo> --verify` reports `verified`/`dead`/`error` for historical findings (network-mocked in tests; live behavior confirmed manually).
3. Non-git path errors cleanly; clean history exits 0 with "no historical secrets".
4. The 4 signature-pack detectors fire on crafted positive fixtures and stay quiet on benign negatives; polyglot degrades gracefully without libmagic.
5. AWS access+secret in the same source verifies as a pair (no longer auto-ERROR).
6. Full suite green at ~285+ tests via system Python.
7. `python-magic` is an optional extra; a fresh `pip install -e .` without it still runs every scan (polyglot just skips).
8. Version bumped to 0.4.0 across `__init__.py`/`pyproject.toml`/`setup.py`; CHANGELOG v0.4.0 section; README + COVERAGE updated; annotated tag `v0.4.0` created locally (NOT pushed — gated on manual smoke verification, per the v0.2/v0.3 pattern).

## 13. Open questions for the implementation plan

Deferred to writing-plans, not blocking spec approval:
- Exact LangGrinch `lc` regex (from research doc / CVE) — see §8.1.
- Whether `git-history` should default `--all` or current-branch (spec chooses `--all`; revisit if noisy).
- Final injection-pattern list and the instruction-file allowlist globs (§8.3) — start conservative, tune against negatives.
- Whether to ship a shared `add_verify_args` refactor commit before the `git-history` command (recommended, to avoid flag duplication).
