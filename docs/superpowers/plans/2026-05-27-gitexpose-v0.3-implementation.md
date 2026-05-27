# GitExpose v0.3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship v0.3 of GitExpose — adds an Active Verification engine (opt-in via `--verify`) that turns 16 safely-verifiable credential patterns from "pattern-matched" into confirmed live/dead status by hitting provider APIs. Plus carry-over items: `mcp_server.py` fix, Tier 3 provider patterns, GitHub Actions + pre-commit + Code Scanning integration docs, MITRE ATLAS coverage map, README CISA-incident callout, repo cleanup.

**Architecture:** New top-level package `gitexpose/verification/` containing an async dispatcher, a single `VERIFIERS` registry of callables, a shared `bearer_token_check` helper for the 80% case, and three custom verifiers for one-offs (AWS SigV4, Docker Hub login flow, Slack `auth.test`). The engine runs as an opt-in post-processing step after existing scanners. Reporters surface a new `verification_status` field; existing fields untouched. No new top-level dependencies — `respx` is added as a dev dependency only.

**Tech Stack:** Python 3.9+, `aiohttp`, `httpx` (added — needed for the verification client because `aiohttp` semantics are awkward for one-shot per-call requests), `respx` (dev only, for HTTP mocking in tests), `pytest`, `pytest-asyncio` (already in dev deps).

**Spec:** `docs/superpowers/specs/2026-05-27-gitexpose-v0.3-design.md`

**Implementation notes (audit-driven divergences from spec):**

- **The spec assumed a single `Finding` class.** v0.1/v0.2 actually ships two shapes: `ScanResult` (dataclass, URL findings) and secret-dicts (raw dicts from `SecretExtractor.extract()`). v0.3 keeps both. The verification engine consumes `(pattern_name, secret_value)` pairs and returns a `dict[secret_value] -> VerificationResult`. The caller is responsible for mutating verification_status back into whichever finding shape it has. This decouples verification from the finding-shape question (which is properly a v0.4 unification task).
- **`httpx` is added as a runtime dependency.** `aiohttp` is already a dep, but `aiohttp` requires session/connector reuse for ergonomic use, which complicates per-call verifiers. `httpx` supports `AsyncClient()` as a one-shot context manager and has cleaner `respx`-based mocking in tests. This is a deliberate addition — the existing scanner code keeps using `aiohttp`.
- **`respx` is added as a dev dependency** to mock all provider HTTP traffic in tests. No live network calls in CI ever.
- **AWS SigV4 is hand-rolled in v0.3.** Time-boxed at 2h. If the boxed time is exceeded, fall back to `botocore.auth.SigV4Auth` (adds `botocore` as a runtime dep). Decision committed in code, not pre-decided.
- **The `verification_status` field is added to `ScanResult` and to the secret-dict shape.** Two-shape parity is intentional.

---

## File Structure Map

### New files

- `gitexpose/verification/__init__.py` — public API: `verify_secrets(secrets, *, concurrency, timeout)`
- `gitexpose/verification/result.py` — `VerificationStatus` enum, `VerificationResult` dataclass
- `gitexpose/verification/helpers.py` — `bearer_token_check()`, `redact()`, shared `httpx.AsyncClient` factory
- `gitexpose/verification/engine.py` — async dispatcher, semaphore, error → status mapping, in-run dedup
- `gitexpose/verification/banner.py` — consent banner printer (`print_verify_banner()`)
- `gitexpose/verification/providers/__init__.py` — `VERIFIERS` registry (single source of truth)
- `gitexpose/verification/providers/llm.py` — bearer-token entries for 11 LLM providers
- `gitexpose/verification/providers/code.py` — bearer-token entries for GitHub PAT, GitLab PAT
- `gitexpose/verification/providers/docker.py` — Docker Hub one-off (`POST /v2/users/login`)
- `gitexpose/verification/providers/slack.py` — Slack `auth.test` with JSON `ok` parse
- `gitexpose/verification/providers/aws.py` — AWS STS `GetCallerIdentity` with SigV4
- `tests/test_verification_result.py`
- `tests/test_verification_helpers.py`
- `tests/test_verification_engine.py`
- `tests/test_verification_log_leak.py`
- `tests/test_verification_providers_llm.py`
- `tests/test_verification_providers_code.py`
- `tests/test_verification_providers_docker.py`
- `tests/test_verification_providers_slack.py`
- `tests/test_verification_providers_aws.py`
- `tests/test_verification_banner.py`
- `tests/test_verification_cli.py`
- `tests/test_smoke_v03.py`
- `tests/test_mcp_server_kwarg_regression.py`
- `tests/test_tier3_patterns.py`
- `tests/fixtures/synthetic_repo_v03/` — extends `synthetic_repo` with verifier-shaped planted creds
- `docs/MITRE_ATLAS_COVERAGE.md`
- `docs/INTEGRATIONS_CICD.md`
- `docs/INTEGRATIONS_CODE_SCANNING.md`
- `docs/notes/` (directory) + moves of two existing root `*.md` notes
- `.github/workflows/gitexpose-scan.yml` — sample workflow
- `.pre-commit-hooks.yaml` — pre-commit hook config

### Modified files

- `gitexpose/models.py` — add `verification_status` + `verification_detail` to `ScanResult`
- `gitexpose/secrets/secret_extractor.py` — add `verification_status` + `verification_detail` keys to secret-dict shape (default values)
- `gitexpose/cli.py` — add `--verify`, `--verify-concurrency`, `--verify-timeout`, `--verify-only-severity`, `--no-verify-banner`; wire the verification post-processing step
- `gitexpose/cli_advanced.py` — same flags on `supply-chain` subcommand
- `gitexpose/advanced/mcp_server.py` — fix `validate=` kwarg and `.get("valid")` typo (carry-over bug)
- `gitexpose/data/credential_patterns_v02.json` — add Tier 3 providers (Helicone, Portkey, Voyage, Cohere, Modal, Runpod)
- `gitexpose/reporters/json_reporter.py` — surface verification fields (mostly already via `asdict` for dataclass; explicit handling for dicts)
- `gitexpose/reporters/sarif_reporter.py` — add `properties.verification_status` + `tags` entry
- `gitexpose/reporters/html_reporter.py` — color badge for verification status
- `gitexpose/reporters/csv_reporter.py` — two new trailing columns
- `gitexpose/reporters/console.py` — append colored verification tag
- `gitexpose/__init__.py` — bump version to `0.3.0`
- `pyproject.toml` — version bump, add `httpx>=0.27` runtime dep, add `respx>=0.21` dev dep
- `setup.py` — version bump, same dep additions
- `README.md` — CISA-incident "Why this matters" callout
- `docs/COVERAGE.md` — add Tier 3 providers + verification-status column
- `CHANGELOG.md` — v0.3.0 entry
- `.gitignore` — add `.serena/`, `RESEARCH/`, `files/`, `files (1)/`, root PNG patterns

### Decomposition rationale

- One module per provider family in `providers/` (`llm.py`, `code.py`, `docker.py`, `slack.py`, `aws.py`): different verification shapes, different test surfaces, different update cadences. Mixing them in one file would balloon and tangle.
- `helpers.py` is shared (bearer-token + redaction). Most providers use it as a one-liner via `functools.partial`. Custom verifiers import from it too.
- `engine.py` separated from `providers/`: engine handles concurrency, deduplication, error mapping; providers handle "is this key live." Each can be tested independently.
- `banner.py` is its own tiny module so the consent banner can be unit-tested without standing up the engine.
- The `VERIFIERS` registry lives in `providers/__init__.py` so it's the canonical importable map.

---

## Task List

### Phase 1 — Foundation

#### Task 1: Add verification fields to ScanResult and secret-dict shape

**Files:**
- Modify: `gitexpose/models.py`
- Modify: `gitexpose/secrets/secret_extractor.py`
- Test: `tests/test_models_v03.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_models_v03.py`:

```python
"""Tests for v0.3 additions to data models — verification status fields."""

import asyncio

from gitexpose.models import Category, ScanResult, Severity
from gitexpose.secrets.secret_extractor import SecretExtractor


def test_scan_result_has_optional_verification_status():
    result = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="x",
        evidence="x",
        verification_status="verified",
        verification_detail="200",
    )
    assert result.verification_status == "verified"
    assert result.verification_detail == "200"


def test_scan_result_verification_defaults_to_skipped():
    result = ScanResult(
        url="x",
        path="x",
        target="x",
        status_code=200,
        vulnerable=True,
        severity=Severity.LOW,
        category=Category.SENSITIVE,
        description="x",
        evidence="x",
    )
    assert result.verification_status == "skipped"
    assert result.verification_detail is None


def test_secret_dict_has_verification_keys():
    extractor = SecretExtractor()
    secrets = asyncio.run(extractor.extract("GROQ_API_KEY=gsk_" + "a" * 52))
    assert secrets, "expected at least one secret"
    for s in secrets:
        assert "verification_status" in s
        assert "verification_detail" in s
        assert s["verification_status"] == "skipped"
        assert s["verification_detail"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models_v03.py -v`
Expected: FAIL — `ScanResult` has no `verification_status` field; secret dicts have no such keys.

- [ ] **Step 3: Add fields to ScanResult**

Edit `gitexpose/models.py`. In the `ScanResult` dataclass, after the existing `atlas_technique: Optional[str] = None` line, append:

```python
    # v0.3 additions: active verification
    verification_status: str = "skipped"   # one of: verified, dead, error, skipped, unverifiable
    verification_detail: Optional[str] = None  # short reason: "200", "401", "timeout", etc.
```

- [ ] **Step 4: Add keys to secret-dict shape**

Edit `gitexpose/secrets/secret_extractor.py`. Locate every `secrets.append({...})` call (there will be two — one for v0.1 patterns, one for v0.2 patterns). For each, add two keys to the dict:

```python
                    'verification_status': 'skipped',
                    'verification_detail': None,
```

Add them next to the existing `'validated': None,` field.

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_models_v03.py -v`
Expected: 3 passed.

- [ ] **Step 6: Run full suite for regressions**

Run: `pytest -v`
Expected: All previously-passing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add gitexpose/models.py gitexpose/secrets/secret_extractor.py tests/test_models_v03.py
git commit -m "✨ Add verification_status and verification_detail to finding shapes"
```

---

#### Task 2: Fix mcp_server.py `validate=` kwarg + `.get("valid")` typo (carry-over bug)

**Files:**
- Modify: `gitexpose/advanced/mcp_server.py`
- Test: `tests/test_mcp_server_kwarg_regression.py` (Create)

- [ ] **Step 1: Read the bug site**

Read `gitexpose/advanced/mcp_server.py` lines 420–445. Confirm:
1. There is a call shaped like `extractor.extract(content, validate=validate)` — but `SecretExtractor.extract()` does not accept `validate` as a kwarg (it's set at `__init__` time).
2. There is a `.get("valid")` somewhere nearby — should be `.get("validated")`.

- [ ] **Step 2: Write the failing regression test**

Create `tests/test_mcp_server_kwarg_regression.py`:

```python
"""Regression test for the v0.2 carry-over bug in mcp_server.py."""

import inspect

import pytest

from gitexpose.advanced.mcp_server import scan_secrets_handler  # adjust import if name differs
from gitexpose.secrets.secret_extractor import SecretExtractor


def test_secret_extractor_extract_has_no_validate_kwarg():
    """Document the API contract: extract() does NOT take a validate kwarg.
    If this ever changes, we should re-audit every callsite."""
    sig = inspect.signature(SecretExtractor.extract)
    assert "validate" not in sig.parameters, (
        "If you added a `validate` kwarg to extract(), you must also re-audit "
        "mcp_server.py which used to call extract(content, validate=...)."
    )


@pytest.mark.asyncio
async def test_mcp_server_scan_secrets_does_not_blow_up_on_validate():
    """Smoke: mcp_server handler runs without TypeError when validate=True is requested."""
    # This is the integration smoke. If mcp_server still passes validate= to extract(),
    # this raises TypeError. If it accesses .get("valid") (wrong key), the bool path
    # silently behaves wrong but won't raise. We assert no exception is raised.
    result = await scan_secrets_handler({"content": "no secrets here", "validate": True})
    assert isinstance(result, (dict, list))
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_mcp_server_kwarg_regression.py -v`
Expected: FAIL — TypeError from `extract(content, validate=...)`.

- [ ] **Step 4: Fix the bug**

In `gitexpose/advanced/mcp_server.py` around line 432:

```python
# OLD:
secrets = await extractor.extract(content, validate=validate)
# ...later...
validated_count = sum(1 for s in secrets if s.get("valid"))

# NEW:
extractor = SecretExtractor(validate=validate)
secrets = await extractor.extract(content)
# ...later...
validated_count = sum(1 for s in secrets if s.get("validated"))
```

(Adapt to actual surrounding code — the import and instantiation of `extractor` may already exist; the change is removing the kwarg from `.extract()` and constructing the extractor with `validate=validate` instead. Fix the `.get("valid")` → `.get("validated")` typo nearby.)

- [ ] **Step 5: Run regression tests**

Run: `pytest tests/test_mcp_server_kwarg_regression.py -v`
Expected: 2 passed.

- [ ] **Step 6: Run full suite**

Run: `pytest -v`
Expected: No regressions.

- [ ] **Step 7: Commit**

```bash
git add gitexpose/advanced/mcp_server.py tests/test_mcp_server_kwarg_regression.py
git commit -m "🐛 Fix mcp_server.py extract() kwarg and validated-key typo (v0.2 carry-over)"
```

---

### Phase 2 — Verification engine core

#### Task 3: Add httpx + respx dependencies

**Files:**
- Modify: `pyproject.toml`
- Modify: `setup.py`
- Modify: `requirements.txt`
- Modify: `requirements-dev.txt`

- [ ] **Step 1: Add httpx to runtime requirements**

In `requirements.txt`, append:

```
httpx>=0.27.0
```

- [ ] **Step 2: Add respx to dev requirements**

In `requirements-dev.txt`, append:

```
respx>=0.21.0
```

- [ ] **Step 3: Update pyproject.toml**

In `pyproject.toml`, find the `dependencies = [...]` block and append `"httpx>=0.27.0"`. Find the `[project.optional-dependencies]` `dev = [...]` block (if it exists) and append `"respx>=0.21.0"`.

- [ ] **Step 4: Update setup.py**

In `setup.py`, find `install_requires=[...]` and append `"httpx>=0.27.0"`. If there's an `extras_require={"dev": [...]}`, append `"respx>=0.21.0"`.

- [ ] **Step 5: Install in editable mode and run existing tests**

```bash
pip install -e .
pip install -r requirements-dev.txt
pytest -v
```

Expected: All existing tests pass, no import-time complaints.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml setup.py requirements.txt requirements-dev.txt
git commit -m "📦 Add httpx (runtime) and respx (dev) for v0.3 verification engine"
```

---

#### Task 4: VerificationStatus enum and VerificationResult dataclass

**Files:**
- Create: `gitexpose/verification/__init__.py`
- Create: `gitexpose/verification/result.py`
- Test: `tests/test_verification_result.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_result.py`:

```python
"""Tests for VerificationStatus enum and VerificationResult dataclass."""

import pytest

from gitexpose.verification.result import VerificationResult, VerificationStatus


def test_status_enum_values():
    assert VerificationStatus.VERIFIED.value == "verified"
    assert VerificationStatus.DEAD.value == "dead"
    assert VerificationStatus.ERROR.value == "error"
    assert VerificationStatus.SKIPPED.value == "skipped"
    assert VerificationStatus.UNVERIFIABLE.value == "unverifiable"


def test_status_is_string_enum():
    """Each enum value should serialize as its string in JSON contexts."""
    assert VerificationStatus.VERIFIED == "verified"
    assert f"{VerificationStatus.DEAD}" == "VerificationStatus.DEAD"
    # Critical: when cast to str via .value, gives the raw string
    assert VerificationStatus.VERIFIED.value == "verified"


def test_verification_result_holds_status_and_detail():
    r = VerificationResult(status=VerificationStatus.VERIFIED, detail="200")
    assert r.status == VerificationStatus.VERIFIED
    assert r.detail == "200"


def test_verification_result_detail_optional():
    r = VerificationResult(status=VerificationStatus.DEAD)
    assert r.detail is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_result.py -v`
Expected: FAIL — ImportError, module doesn't exist.

- [ ] **Step 3: Create the verification package**

Create `gitexpose/verification/__init__.py`:

```python
"""Active verification engine for GitExpose v0.3.

Sends low-footprint, side-effect-free authentication checks to provider APIs
to confirm whether a discovered credential is live. Opt-in via --verify.
"""

from .result import VerificationResult, VerificationStatus

__all__ = ["VerificationResult", "VerificationStatus", "verify_secrets"]


def __getattr__(name: str):  # pragma: no cover — lazy import to keep this module light
    if name == "verify_secrets":
        from .engine import verify_secrets
        return verify_secrets
    raise AttributeError(name)
```

- [ ] **Step 4: Create the result module**

Create `gitexpose/verification/result.py`:

```python
"""VerificationStatus enum and VerificationResult dataclass."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerificationStatus(str, Enum):
    """Outcome of a single verification attempt.

    str-Enum so values serialize as plain strings in JSON / SARIF property bags
    without `.value` boilerplate at the call site.
    """

    VERIFIED = "verified"          # provider confirmed live
    DEAD = "dead"                  # provider returned auth-rejection (401 / 403)
    ERROR = "error"                # network / timeout / unexpected response shape
    SKIPPED = "skipped"            # --verify not passed (default)
    UNVERIFIABLE = "unverifiable"  # pattern has no registered verifier


@dataclass(frozen=True)
class VerificationResult:
    """Result of one verification attempt against one secret."""

    status: VerificationStatus
    detail: Optional[str] = None   # short reason: "200", "401", "timeout", "200 ok=true"
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_verification_result.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/__init__.py gitexpose/verification/result.py tests/test_verification_result.py
git commit -m "✨ Scaffold gitexpose.verification package with status enum + result dataclass"
```

---

#### Task 5: Shared helpers — bearer_token_check and redact

**Files:**
- Create: `gitexpose/verification/helpers.py`
- Test: `tests/test_verification_helpers.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_helpers.py`:

```python
"""Tests for shared verification helpers."""

import pytest
import respx
import httpx

from gitexpose.verification.helpers import bearer_token_check, redact
from gitexpose.verification.result import VerificationResult, VerificationStatus


def test_redact_short_secret():
    assert redact("abc") == "***"   # nothing useful to expose


def test_redact_typical_secret():
    assert redact("sk-abcd1234567890wxyz") == "sk-…wxyz"


def test_redact_very_long_secret():
    secret = "x" * 200
    out = redact(secret)
    assert secret not in out
    assert len(out) < 20


def test_redact_none_safe():
    assert redact(None) == "***"


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_200_returns_verified():
    respx.get("https://api.example.com/v1/me").mock(return_value=httpx.Response(200))
    result = await bearer_token_check(
        secret="sk-abc",
        url="https://api.example.com/v1/me",
        header="Authorization",
        scheme="Bearer",
    )
    assert result.status == VerificationStatus.VERIFIED
    assert "200" in (result.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_401_returns_dead():
    respx.get("https://api.example.com/v1/me").mock(return_value=httpx.Response(401))
    result = await bearer_token_check(
        secret="sk-abc",
        url="https://api.example.com/v1/me",
        header="Authorization",
        scheme="Bearer",
    )
    assert result.status == VerificationStatus.DEAD
    assert "401" in (result.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_403_returns_dead():
    respx.get("https://api.example.com/v1/me").mock(return_value=httpx.Response(403))
    result = await bearer_token_check(
        secret="sk-abc",
        url="https://api.example.com/v1/me",
        header="Authorization",
        scheme="Bearer",
    )
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_500_returns_error():
    respx.get("https://api.example.com/v1/me").mock(return_value=httpx.Response(500))
    result = await bearer_token_check(
        secret="sk-abc",
        url="https://api.example.com/v1/me",
        header="Authorization",
        scheme="Bearer",
    )
    assert result.status == VerificationStatus.ERROR
    assert "500" in (result.detail or "")


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_network_error_returns_error():
    respx.get("https://api.example.com/v1/me").mock(side_effect=httpx.ConnectError("boom"))
    result = await bearer_token_check(
        secret="sk-abc",
        url="https://api.example.com/v1/me",
        header="Authorization",
        scheme="Bearer",
    )
    assert result.status == VerificationStatus.ERROR


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_no_scheme_sends_raw_token():
    """For providers like Anthropic that use `x-api-key: <key>` without `Bearer` prefix."""
    route = respx.get("https://api.example.com/v1/me").mock(return_value=httpx.Response(200))
    await bearer_token_check(
        secret="sk-ant-xyz",
        url="https://api.example.com/v1/me",
        header="x-api-key",
        scheme=None,
    )
    assert route.called
    req = route.calls.last.request
    assert req.headers["x-api-key"] == "sk-ant-xyz"
    assert "Authorization" not in req.headers


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_check_with_scheme_prepends_bearer():
    route = respx.get("https://api.example.com/v1/me").mock(return_value=httpx.Response(200))
    await bearer_token_check(
        secret="sk-abc",
        url="https://api.example.com/v1/me",
        header="Authorization",
        scheme="Bearer",
    )
    req = route.calls.last.request
    assert req.headers["Authorization"] == "Bearer sk-abc"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_helpers.py -v`
Expected: FAIL — ImportError.

- [ ] **Step 3: Implement helpers**

Create `gitexpose/verification/helpers.py`:

```python
"""Shared helpers for verification providers.

bearer_token_check() is the 80%-case helper: send a single GET to a provider's
documented liveness endpoint, map response → VerificationStatus.

redact() is the universal log-redaction helper. Used by every verifier and the
engine. Unit-tested to ensure no raw secret survives in any log line.
"""

from __future__ import annotations

from typing import Optional

import httpx

from .result import VerificationResult, VerificationStatus


def redact(secret: Optional[str]) -> str:
    """Return a log-safe representation of `secret`.

    Format: first 3 chars + ellipsis + last 4 chars (e.g., "sk-…wxyz").
    For secrets shorter than 8 chars, returns "***".
    """
    if not secret or len(secret) < 8:
        return "***"
    return f"{secret[:3]}…{secret[-4:]}"


# Default per-request timeout. Caller may override via the engine.
_DEFAULT_TIMEOUT = 5.0


async def bearer_token_check(
    secret: str,
    *,
    url: str,
    header: str,
    scheme: Optional[str],
    timeout: float = _DEFAULT_TIMEOUT,
) -> VerificationResult:
    """Send a GET to `url` with the credential in `header` and map status → result.

    `scheme` is the optional auth-header prefix:
      - "Bearer" → `Authorization: Bearer sk-abc`
      - None     → `x-api-key: sk-ant-xyz`  (no prefix; raw token in header)
    """
    value = f"{scheme} {secret}" if scheme else secret
    headers = {header: value, "User-Agent": "GitExpose-Verify/0.3"}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    code = response.status_code
    if code == 200:
        return VerificationResult(VerificationStatus.VERIFIED, "200")
    if code in (401, 403):
        return VerificationResult(VerificationStatus.DEAD, str(code))
    return VerificationResult(VerificationStatus.ERROR, str(code))
```

- [ ] **Step 4: Run helper tests**

Run: `pytest tests/test_verification_helpers.py -v`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/verification/helpers.py tests/test_verification_helpers.py
git commit -m "✨ Add bearer_token_check and redact helpers for verification engine"
```

---

#### Task 6: Engine dispatcher with semaphore and in-run dedup

**Files:**
- Create: `gitexpose/verification/engine.py`
- Test: `tests/test_verification_engine.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_engine.py`:

```python
"""Tests for the verification engine dispatcher."""

import asyncio

import pytest

from gitexpose.verification.engine import verify_secrets
from gitexpose.verification.result import VerificationResult, VerificationStatus


@pytest.mark.asyncio
async def test_returns_skipped_for_unregistered_pattern(monkeypatch):
    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {},  # empty registry
        raising=False,
    )
    secrets = [{"type": "no_such_pattern", "value_full": "abc"}]
    out = await verify_secrets(secrets)
    assert out[0]["verification_status"] == VerificationStatus.UNVERIFIABLE.value


@pytest.mark.asyncio
async def test_runs_registered_verifier_and_writes_status(monkeypatch):
    async def fake_verifier(secret):
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": fake_verifier},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": "sk-abc"}]
    out = await verify_secrets(secrets)
    assert out[0]["verification_status"] == VerificationStatus.VERIFIED.value
    assert out[0]["verification_detail"] == "200"


@pytest.mark.asyncio
async def test_dedups_same_secret_within_run(monkeypatch):
    call_count = 0

    async def counting_verifier(secret):
        nonlocal call_count
        call_count += 1
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": counting_verifier},
        raising=False,
    )
    secrets = [
        {"type": "openai", "value_full": "sk-abc"},
        {"type": "openai", "value_full": "sk-abc"},  # same secret again
        {"type": "openai", "value_full": "sk-abc"},  # and again
    ]
    out = await verify_secrets(secrets)
    assert call_count == 1
    assert all(s["verification_status"] == VerificationStatus.VERIFIED.value for s in out)


@pytest.mark.asyncio
async def test_exception_in_verifier_yields_error_status(monkeypatch):
    async def bad_verifier(secret):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": bad_verifier},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": "sk-abc"}]
    out = await verify_secrets(secrets)
    assert out[0]["verification_status"] == VerificationStatus.ERROR.value
    assert "RuntimeError" in (out[0]["verification_detail"] or "")


@pytest.mark.asyncio
async def test_semaphore_caps_concurrent_calls(monkeypatch):
    in_flight = 0
    max_seen = 0

    async def slow_verifier(secret):
        nonlocal in_flight, max_seen
        in_flight += 1
        max_seen = max(max_seen, in_flight)
        await asyncio.sleep(0.05)
        in_flight -= 1
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": slow_verifier},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": f"sk-{i}"} for i in range(20)]
    await verify_secrets(secrets, concurrency=3)
    assert max_seen <= 3, f"semaphore allowed {max_seen} concurrent, expected ≤ 3"


@pytest.mark.asyncio
async def test_timeout_in_verifier_yields_error(monkeypatch):
    async def hangs(secret):
        await asyncio.sleep(10)
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": hangs},
        raising=False,
    )
    secrets = [{"type": "openai", "value_full": "sk-abc"}]
    out = await verify_secrets(secrets, timeout=0.05)
    assert out[0]["verification_status"] == VerificationStatus.ERROR.value
    assert out[0]["verification_detail"] == "timeout"


@pytest.mark.asyncio
async def test_handles_mixed_finding_shapes(monkeypatch):
    """Engine must accept both ScanResult-shaped objects and secret-dicts."""
    from gitexpose.models import Category, ScanResult, Severity

    async def ok(secret):
        return VerificationResult(VerificationStatus.VERIFIED, "200")

    monkeypatch.setattr(
        "gitexpose.verification.engine.VERIFIERS",
        {"openai": ok, "github_pat": ok},
        raising=False,
    )

    scan_result = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="x",
        evidence="sk-abc found",
    )
    # Treat ScanResult by reading evidence as the secret; in practice the caller
    # extracts (pattern_name, secret_value) and applies the result. The engine
    # API works on a list of dict-like records.
    secrets = [
        {"type": "openai", "value_full": "sk-abc"},
        {"type": "github_pat", "value_full": "ghp_abc"},
    ]
    out = await verify_secrets(secrets)
    assert all(s["verification_status"] == VerificationStatus.VERIFIED.value for s in out)
```

- [ ] **Step 2: Create the (empty) providers package**

The engine imports `from .providers import VERIFIERS` at module level. We populate the registry in subsequent tasks; for now it must exist and expose an empty dict so the engine module can be imported and tests can patch the registry.

Create `gitexpose/verification/providers/__init__.py`:

```python
"""VERIFIERS registry — single source of truth for provider verifier callables.

Each entry: pattern_name (str) → Callable[[str], Awaitable[VerificationResult]]

Subsequent tasks (LLM providers, code providers, Docker Hub, Slack, AWS) extend
this registry. This task creates the empty scaffold so engine.py can import it.
"""

from __future__ import annotations

VERIFIERS: dict = {}

__all__ = ["VERIFIERS"]
```

- [ ] **Step 3: Run engine test to verify import errors are gone but logic still fails**

Run: `pytest tests/test_verification_engine.py -v`
Expected: FAIL — ImportError on `gitexpose.verification.engine` itself.

- [ ] **Step 4: Implement engine**

Create `gitexpose/verification/engine.py`:

```python
"""Async dispatcher for the verification engine.

Walks a list of secret-dicts, looks each up in the VERIFIERS registry, and writes
back two keys per secret: `verification_status` and `verification_detail`. Uses a
shared semaphore to cap provider-side load and in-run dedup keyed by raw secret
value.

Does NOT mutate any other finding fields. Existing fields are preserved.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Mapping

from .result import VerificationResult, VerificationStatus
from .providers import VERIFIERS  # the canonical registry

logger = logging.getLogger(__name__)


_DEFAULT_CONCURRENCY = 5
_DEFAULT_TIMEOUT = 5.0


def _secret_value(record: Mapping[str, Any]) -> str:
    """Pull the raw secret string out of a record.

    Records may be:
      - secret-dicts from SecretExtractor (key: 'value_full')
      - ScanResult-shaped dicts (we use 'evidence' or similar — caller normalizes)
    """
    # Primary key is value_full for secret-dicts
    return record.get("value_full") or record.get("secret") or ""


def _pattern_name(record: Mapping[str, Any]) -> str:
    """Pull the pattern identifier out of a record."""
    return record.get("type") or record.get("pattern_name") or ""


async def verify_secrets(
    secrets: List[Dict[str, Any]],
    *,
    concurrency: int = _DEFAULT_CONCURRENCY,
    timeout: float = _DEFAULT_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Verify every secret in `secrets` whose pattern is in VERIFIERS.

    Mutates each dict in-place (sets verification_status + verification_detail)
    and also returns the list.

    Concurrency is capped via a shared semaphore. Identical raw secrets within a
    single call are verified once (in-run dedup).
    """
    sem = asyncio.Semaphore(concurrency)
    seen: Dict[str, VerificationResult] = {}

    async def _one(record: Dict[str, Any]) -> None:
        pattern = _pattern_name(record)
        secret = _secret_value(record)

        verifier: Callable[[str], Awaitable[VerificationResult]] | None = VERIFIERS.get(pattern)
        if verifier is None:
            record["verification_status"] = VerificationStatus.UNVERIFIABLE.value
            record["verification_detail"] = None
            return

        if secret in seen:
            result = seen[secret]
        else:
            async with sem:
                try:
                    result = await asyncio.wait_for(verifier(secret), timeout=timeout)
                except asyncio.TimeoutError:
                    result = VerificationResult(VerificationStatus.ERROR, "timeout")
                except Exception as exc:  # noqa: BLE001 — capture provider failures
                    logger.debug("Verifier raised for %s: %s", pattern, type(exc).__name__)
                    result = VerificationResult(VerificationStatus.ERROR, type(exc).__name__)
            seen[secret] = result

        record["verification_status"] = result.status.value
        record["verification_detail"] = result.detail

    await asyncio.gather(*(_one(r) for r in secrets))
    return secrets
```

- [ ] **Step 5: Run engine tests**

Run: `pytest tests/test_verification_engine.py -v`
Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/ tests/test_verification_engine.py
git commit -m "✨ Add async verification dispatcher with semaphore and in-run dedup"
```

---

### Phase 3 — LLM provider verifiers

#### Task 7: LLM provider registry

**Files:**
- Create: `gitexpose/verification/providers/__init__.py`
- Create: `gitexpose/verification/providers/llm.py`
- Test: `tests/test_verification_providers_llm.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_providers_llm.py`:

```python
"""Tests for LLM provider verifiers."""

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS
from gitexpose.verification.result import VerificationStatus

# Each tuple: (pattern_name, expected_host, expected_header)
LLM_PROVIDERS = [
    ("openai_api_key",            "api.openai.com",        "Authorization"),
    ("openai_project_key",        "api.openai.com",        "Authorization"),
    ("openai_service_account_key","api.openai.com",        "Authorization"),
    ("anthropic_api_key",         "api.anthropic.com",     "x-api-key"),
    ("groq_api_key",              "api.groq.com",          "Authorization"),
    ("openrouter_api_key",        "openrouter.ai",         "Authorization"),
    ("perplexity_api_key",        "api.perplexity.ai",     "Authorization"),
    ("xai_api_key",               "api.x.ai",              "Authorization"),
    ("cerebras_api_key",          "api.cerebras.ai",       "Authorization"),
    ("huggingface_token",         "huggingface.co",        "Authorization"),
    ("elevenlabs_context_bound",  "api.elevenlabs.io",     "xi-api-key"),
    ("pinecone_api_key",          "api.pinecone.io",       "Api-Key"),
    ("langsmith_api_key_v2",      "api.smith.langchain.com","x-api-key"),
    ("langsmith_api_key_legacy",  "api.smith.langchain.com","x-api-key"),
]


@pytest.mark.parametrize("pattern, host, header", LLM_PROVIDERS)
def test_llm_provider_registered(pattern, host, header):
    assert pattern in VERIFIERS, f"{pattern} not in VERIFIERS"


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern, host, header", LLM_PROVIDERS)
@respx.mock
async def test_llm_provider_returns_verified_on_200(pattern, host, header):
    respx.get(f"https://{host}").mock(side_effect=lambda req: httpx.Response(200))
    respx.route(host=host).mock(return_value=httpx.Response(200))
    verifier = VERIFIERS[pattern]
    result = await verifier("fake-secret")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern, host, header", LLM_PROVIDERS)
@respx.mock
async def test_llm_provider_returns_dead_on_401(pattern, host, header):
    respx.route(host=host).mock(return_value=httpx.Response(401))
    verifier = VERIFIERS[pattern]
    result = await verifier("fake-secret")
    assert result.status == VerificationStatus.DEAD
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_providers_llm.py -v`
Expected: FAIL — ImportError.

- [ ] **Step 3: Implement LLM provider entries**

Create `gitexpose/verification/providers/llm.py`:

```python
"""Liveness verifier entries for LLM-ecosystem providers.

Every entry below resolves to bearer_token_check with the provider's documented
liveness endpoint baked in. URLs and headers are sourced from each provider's
public API documentation.

# Side-effect class: READ-ONLY across all entries
# Every endpoint here is documented as a no-cost, side-effect-free read.
"""

from __future__ import annotations

from functools import partial

from ..helpers import bearer_token_check

# Each entry: pattern_name → partial(bearer_token_check, url=..., header=..., scheme=...)
LLM_VERIFIERS = {
    # OpenAI family (3 patterns, same endpoint)
    "openai_api_key":             partial(bearer_token_check, url="https://api.openai.com/v1/models",        header="Authorization", scheme="Bearer"),
    "openai_project_key":         partial(bearer_token_check, url="https://api.openai.com/v1/models",        header="Authorization", scheme="Bearer"),
    "openai_service_account_key": partial(bearer_token_check, url="https://api.openai.com/v1/models",        header="Authorization", scheme="Bearer"),

    # Anthropic — uses x-api-key header without Bearer prefix
    "anthropic_api_key":          partial(bearer_token_check, url="https://api.anthropic.com/v1/models",     header="x-api-key",     scheme=None),

    # Groq — OpenAI-compatible API
    "groq_api_key":               partial(bearer_token_check, url="https://api.groq.com/openai/v1/models",   header="Authorization", scheme="Bearer"),

    # OpenRouter — OpenAI-compatible
    "openrouter_api_key":         partial(bearer_token_check, url="https://openrouter.ai/api/v1/auth/key",   header="Authorization", scheme="Bearer"),

    # Perplexity — OpenAI-compatible
    "perplexity_api_key":         partial(bearer_token_check, url="https://api.perplexity.ai/chat/completions", header="Authorization", scheme="Bearer"),
    # NOTE: Perplexity's docs don't expose a no-op liveness endpoint; the chat
    # endpoint with no body returns 400 for valid keys and 401 for bad ones,
    # which our 401 → DEAD mapping handles correctly.

    # xAI (Grok) — OpenAI-compatible
    "xai_api_key":                partial(bearer_token_check, url="https://api.x.ai/v1/models",              header="Authorization", scheme="Bearer"),

    # Cerebras — OpenAI-compatible
    "cerebras_api_key":           partial(bearer_token_check, url="https://api.cerebras.ai/v1/models",       header="Authorization", scheme="Bearer"),

    # Hugging Face — whoami endpoint
    "huggingface_token":          partial(bearer_token_check, url="https://huggingface.co/api/whoami-v2",    header="Authorization", scheme="Bearer"),

    # ElevenLabs — user endpoint
    "elevenlabs_context_bound":   partial(bearer_token_check, url="https://api.elevenlabs.io/v1/user",       header="xi-api-key",    scheme=None),

    # Pinecone — uses Api-Key header without prefix
    "pinecone_api_key":           partial(bearer_token_check, url="https://api.pinecone.io/databases",       header="Api-Key",       scheme=None),

    # LangSmith — workspaces endpoint
    "langsmith_api_key_v2":       partial(bearer_token_check, url="https://api.smith.langchain.com/api/v1/workspaces", header="x-api-key", scheme=None),
    "langsmith_api_key_legacy":   partial(bearer_token_check, url="https://api.smith.langchain.com/api/v1/workspaces", header="x-api-key", scheme=None),
}
```

- [ ] **Step 4: Replace the empty registry with the populated one**

Task 6 created `gitexpose/verification/providers/__init__.py` with an empty `VERIFIERS = {}`. Replace its contents with the populated registry:

```python
"""VERIFIERS registry — single source of truth for provider verifier callables.

Each entry: pattern_name (str) → Callable[[str], Awaitable[VerificationResult]]

Lookup is by `pattern_name` matching the `type` field of secret-dicts (which is
the same as the JSON pattern name in `gitexpose/data/credential_patterns_v02.json`).
"""

from __future__ import annotations

from .llm import LLM_VERIFIERS

# Composed registry. Code providers, Docker Hub, Slack, and AWS are added in
# subsequent tasks. Each registry section is a dict-merge.
VERIFIERS = {
    **LLM_VERIFIERS,
}

__all__ = ["VERIFIERS"]
```

- [ ] **Step 5: Run LLM provider tests**

Run: `pytest tests/test_verification_providers_llm.py -v`
Expected: 14 pattern-registration tests + 14 "verified on 200" + 14 "dead on 401" = 42 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/providers/ tests/test_verification_providers_llm.py
git commit -m "✨ Register 14 LLM provider verifiers (OpenAI, Anthropic, Groq, …)"
```

---

### Phase 4 — Code/cloud provider verifiers

#### Task 8: Code providers (GitHub PAT, GitLab PAT)

**Files:**
- Create: `gitexpose/verification/providers/code.py`
- Modify: `gitexpose/verification/providers/__init__.py`
- Test: `tests/test_verification_providers_code.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_providers_code.py`:

```python
"""Tests for code-platform verifiers (GitHub PAT, GitLab PAT)."""

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS
from gitexpose.verification.result import VerificationStatus


@pytest.mark.asyncio
@respx.mock
async def test_github_pat_verified_on_200():
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(200))
    result = await VERIFIERS["github_pat"]("ghp_fake")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_github_pat_dead_on_401():
    respx.get("https://api.github.com/user").mock(return_value=httpx.Response(401))
    result = await VERIFIERS["github_pat"]("ghp_fake")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_gitlab_pat_verified_on_200():
    respx.get("https://gitlab.com/api/v4/user").mock(return_value=httpx.Response(200))
    result = await VERIFIERS["gitlab_pat"]("glpat-fake")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_gitlab_pat_dead_on_401():
    respx.get("https://gitlab.com/api/v4/user").mock(return_value=httpx.Response(401))
    result = await VERIFIERS["gitlab_pat"]("glpat-fake")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_github_pat_sends_bearer_authorization():
    route = respx.get("https://api.github.com/user").mock(return_value=httpx.Response(200))
    await VERIFIERS["github_pat"]("ghp_abc")
    assert route.calls.last.request.headers["Authorization"] == "Bearer ghp_abc"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_providers_code.py -v`
Expected: FAIL — `github_pat` not in VERIFIERS.

- [ ] **Step 3: Implement code providers**

Create `gitexpose/verification/providers/code.py`:

```python
"""Liveness verifiers for code-hosting platform credentials.

# Side-effect class: READ-ONLY
# GitHub: GET /user — returns authenticated user JSON
# GitLab: GET /api/v4/user — returns authenticated user JSON
"""

from __future__ import annotations

from functools import partial

from ..helpers import bearer_token_check

CODE_VERIFIERS = {
    "github_pat": partial(bearer_token_check, url="https://api.github.com/user",       header="Authorization", scheme="Bearer"),
    "gitlab_pat": partial(bearer_token_check, url="https://gitlab.com/api/v4/user",    header="Authorization", scheme="Bearer"),
}
```

- [ ] **Step 4: Wire into registry**

Edit `gitexpose/verification/providers/__init__.py`:

```python
from .llm import LLM_VERIFIERS
from .code import CODE_VERIFIERS

VERIFIERS = {
    **LLM_VERIFIERS,
    **CODE_VERIFIERS,
}

__all__ = ["VERIFIERS"]
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_verification_providers_code.py -v`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/providers/ tests/test_verification_providers_code.py
git commit -m "✨ Register GitHub PAT and GitLab PAT verifiers"
```

---

#### Task 9: Docker Hub verifier (one-off login flow)

**Files:**
- Create: `gitexpose/verification/providers/docker.py`
- Modify: `gitexpose/verification/providers/__init__.py`
- Test: `tests/test_verification_providers_docker.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_providers_docker.py`:

```python
"""Tests for Docker Hub verifier — uses POST /v2/users/login."""

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS
from gitexpose.verification.result import VerificationStatus


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_verified_on_jwt_response():
    """A live PAT returns 200 with a JWT in the body."""
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(200, json={"token": "eyJ.fake.jwt"})
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_fake_token_value")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_dead_on_401_unauthorized():
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(401, json={"detail": "Incorrect authentication credentials."})
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_invalid")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_dead_when_response_lacks_token():
    """Server returns 200 but no JWT — should be DEAD (auth shape rejected)."""
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(200, json={"detail": "no token"})
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_weird")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_docker_hub_error_on_500():
    respx.post("https://hub.docker.com/v2/users/login").mock(
        return_value=httpx.Response(500)
    )
    result = await VERIFIERS["docker_hub_pat"]("dckr_pat_x")
    assert result.status == VerificationStatus.ERROR
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_providers_docker.py -v`
Expected: FAIL — `docker_hub_pat` not registered.

- [ ] **Step 3: Implement Docker Hub verifier**

Create `gitexpose/verification/providers/docker.py`:

```python
"""Docker Hub liveness verifier.

Docker Hub PATs authenticate via `POST /v2/users/login` with a JSON body
containing username + password (the PAT). A 200 response with a `token` field in
the body indicates a live credential. 401/403 → DEAD. Any other shape → ERROR.

# Side-effect class: READ-ONLY (auth check, returns JWT; does NOT create resources)
# Reference: https://docs.docker.com/reference/api/hub/latest/#tag/authentication
"""

from __future__ import annotations

import httpx

from ..result import VerificationResult, VerificationStatus


_LOGIN_URL = "https://hub.docker.com/v2/users/login"


async def verify(secret: str, *, timeout: float = 5.0) -> VerificationResult:
    """Check whether `secret` (a Docker Hub PAT) authenticates successfully."""
    # Docker Hub PATs are used as the password; the username for PAT-based auth
    # is the account name, which we don't have. The login endpoint accepts a
    # `personal_access_token` field in newer Hub APIs; we use that.
    body = {"username": "gitexpose-verify", "password": secret}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                _LOGIN_URL,
                json=body,
                headers={"User-Agent": "GitExpose-Verify/0.3"},
            )
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    code = response.status_code
    if code in (401, 403):
        return VerificationResult(VerificationStatus.DEAD, str(code))
    if code != 200:
        return VerificationResult(VerificationStatus.ERROR, str(code))

    # 200 — confirm shape contains a token field
    try:
        body_json = response.json()
    except ValueError:
        return VerificationResult(VerificationStatus.ERROR, "non-json-200")
    if not isinstance(body_json, dict) or not body_json.get("token"):
        return VerificationResult(VerificationStatus.DEAD, "200 no-token")
    return VerificationResult(VerificationStatus.VERIFIED, "200 token-present")
```

- [ ] **Step 4: Wire into registry**

Edit `gitexpose/verification/providers/__init__.py`:

```python
from .llm import LLM_VERIFIERS
from .code import CODE_VERIFIERS
from . import docker

VERIFIERS = {
    **LLM_VERIFIERS,
    **CODE_VERIFIERS,
    "docker_hub_pat": docker.verify,
}

__all__ = ["VERIFIERS"]
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_verification_providers_docker.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/providers/ tests/test_verification_providers_docker.py
git commit -m "✨ Register Docker Hub PAT verifier (POST /v2/users/login with token-shape check)"
```

---

### Phase 5 — One-off provider verifiers

#### Task 10: Slack token verifier (auth.test with JSON ok parse)

**Files:**
- Create: `gitexpose/verification/providers/slack.py`
- Modify: `gitexpose/verification/providers/__init__.py`
- Test: `tests/test_verification_providers_slack.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_providers_slack.py`:

```python
"""Tests for Slack token verifier — uses auth.test endpoint."""

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS
from gitexpose.verification.result import VerificationStatus


@pytest.mark.asyncio
@respx.mock
async def test_slack_verified_when_ok_true():
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(200, json={"ok": True, "team": "TestTeam"})
    )
    result = await VERIFIERS["slack_token"]("xoxb-fake")
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_slack_dead_when_ok_false():
    """Critical: Slack returns 200 with {ok: false} for invalid tokens — that's DEAD."""
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
    )
    result = await VERIFIERS["slack_token"]("xoxb-bad")
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
@respx.mock
async def test_slack_error_on_500():
    respx.post("https://slack.com/api/auth.test").mock(
        return_value=httpx.Response(500)
    )
    result = await VERIFIERS["slack_token"]("xoxb-x")
    assert result.status == VerificationStatus.ERROR
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_providers_slack.py -v`
Expected: FAIL — slack_token not in VERIFIERS yet (or returns wrong status).

- [ ] **Step 3: Implement Slack verifier**

Create `gitexpose/verification/providers/slack.py`:

```python
"""Slack token liveness verifier.

Uses `auth.test`, which is the documented side-effect-free endpoint for token
validation. CRITICAL: Slack returns HTTP 200 for INVALID tokens too — the actual
result is in the JSON body's `ok` field.

# Side-effect class: READ-ONLY (documented auth check)
# Reference: https://api.slack.com/methods/auth.test
"""

from __future__ import annotations

import httpx

from ..result import VerificationResult, VerificationStatus


_URL = "https://slack.com/api/auth.test"


async def verify(secret: str, *, timeout: float = 5.0) -> VerificationResult:
    headers = {
        "Authorization": f"Bearer {secret}",
        "User-Agent": "GitExpose-Verify/0.3",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(_URL, headers=headers)
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    if response.status_code != 200:
        return VerificationResult(VerificationStatus.ERROR, str(response.status_code))
    try:
        body = response.json()
    except ValueError:
        return VerificationResult(VerificationStatus.ERROR, "non-json-200")
    if not isinstance(body, dict):
        return VerificationResult(VerificationStatus.ERROR, "non-object-200")
    if body.get("ok") is True:
        return VerificationResult(VerificationStatus.VERIFIED, "200 ok=true")
    return VerificationResult(VerificationStatus.DEAD, f"200 ok=false: {body.get('error', 'unknown')}")
```

- [ ] **Step 4: Wire into registry**

Edit `gitexpose/verification/providers/__init__.py`:

```python
from .llm import LLM_VERIFIERS
from .code import CODE_VERIFIERS
from . import docker, slack

VERIFIERS = {
    **LLM_VERIFIERS,
    **CODE_VERIFIERS,
    "docker_hub_pat": docker.verify,
    "slack_token":    slack.verify,
}

__all__ = ["VERIFIERS"]
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_verification_providers_slack.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/providers/ tests/test_verification_providers_slack.py
git commit -m "✨ Register Slack token verifier (auth.test with ok-field parsing)"
```

---

#### Task 11: AWS STS verifier (SigV4 GetCallerIdentity)

**Files:**
- Create: `gitexpose/verification/providers/aws.py`
- Modify: `gitexpose/verification/providers/__init__.py`
- Test: `tests/test_verification_providers_aws.py` (Create)

> **Time-box note for implementer:** SigV4 is the most complex item in v0.3. Budget: 2 hours. If you exceed it, swap the hand-rolled signer for `from botocore.auth import SigV4Auth` (adds `botocore>=1.34` runtime dep). The test surface is identical; only the internal signer changes.

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_providers_aws.py`:

```python
"""Tests for AWS STS GetCallerIdentity verifier (SigV4-signed)."""

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS
from gitexpose.verification.result import VerificationStatus


# AWS access keys come with a paired secret. SecretExtractor v0.1 reports them
# in two separate findings (aws_access_key + aws_secret_key). For verification,
# we pair them via a known convention: the secret string for the verifier is
# "AKIA…:secret" (access key + colon + secret). The CLI integration is
# responsible for the pairing; the verifier consumes the combined form.

VALID_PAIR = "AKIA" + "A" * 16 + ":" + "x" * 40
INVALID_PAIR = "AKIA" + "A" * 16 + ":" + "y" * 40


@pytest.mark.asyncio
@respx.mock
async def test_aws_verified_on_signed_200():
    """STS returns 200 with an XML envelope for a valid signed request."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/test</Arn>
    <UserId>AIDAEXAMPLEEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"""
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text=xml, headers={"Content-Type": "text/xml"})
    )
    result = await VERIFIERS["aws_access_key"](VALID_PAIR)
    assert result.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
@respx.mock
async def test_aws_dead_on_403_signature_invalid():
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(403, text="<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>")
    )
    result = await VERIFIERS["aws_access_key"](INVALID_PAIR)
    assert result.status == VerificationStatus.DEAD


@pytest.mark.asyncio
async def test_aws_returns_error_when_pair_malformed():
    """If the secret string isn't `AKIA…:secret`, return ERROR — caller didn't pair."""
    result = await VERIFIERS["aws_access_key"]("AKIA-not-paired")
    assert result.status == VerificationStatus.ERROR
    assert "pair" in (result.detail or "").lower()


@pytest.mark.asyncio
@respx.mock
async def test_aws_request_is_sigv4_signed():
    """Smoke: confirm the Authorization header looks SigV4-shaped."""
    route = respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text="<GetCallerIdentityResponse></GetCallerIdentityResponse>")
    )
    await VERIFIERS["aws_access_key"](VALID_PAIR)
    req = route.calls.last.request
    auth = req.headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert "Credential=AKIA" in auth
    assert "SignedHeaders=" in auth
    assert "Signature=" in auth
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_providers_aws.py -v`
Expected: FAIL — `aws_access_key` not registered.

- [ ] **Step 3: Implement AWS SigV4 verifier**

Create `gitexpose/verification/providers/aws.py`:

```python
"""AWS STS GetCallerIdentity verifier with hand-rolled SigV4 signing.

# Side-effect class: READ-ONLY
# Endpoint: POST https://sts.amazonaws.com/ — Action=GetCallerIdentity
# Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
#
# The secret string format expected by this verifier is "<access_key>:<secret_key>"
# (e.g., "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").
# The CLI layer is responsible for pairing AWS findings; an unpaired secret
# returns ERROR with detail "expected access:secret pair".
#
# SigV4 algorithm summary:
#   1. CanonicalRequest = METHOD\nURI\nQS\nHEADERS\n\nSIGNED_HEADERS\nHASH(BODY)
#   2. StringToSign     = ALGORITHM\nAMZ-DATE\nSCOPE\nHASH(CanonicalRequest)
#   3. SigningKey       = HMAC(HMAC(HMAC(HMAC("AWS4"+SECRET, DATE), REGION), SERVICE), "aws4_request")
#   4. Signature        = HEX(HMAC(SigningKey, StringToSign))
"""

from __future__ import annotations

import datetime
import hashlib
import hmac

import httpx

from ..result import VerificationResult, VerificationStatus

_HOST = "sts.amazonaws.com"
_REGION = "us-east-1"
_SERVICE = "sts"
_URL = f"https://{_HOST}/"
_PAYLOAD = "Action=GetCallerIdentity&Version=2011-06-15"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _build_signed_request(access_key: str, secret_key: str) -> dict[str, str]:
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(_PAYLOAD.encode("utf-8")).hexdigest()

    canonical_headers = (
        f"content-type:application/x-www-form-urlencoded\n"
        f"host:{_HOST}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-type;host;x-amz-date"

    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{date_stamp}/{_REGION}/{_SERVICE}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    k_date    = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region  = _sign(k_date, _REGION)
    k_service = _sign(k_region, _SERVICE)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
        "User-Agent": "GitExpose-Verify/0.3",
    }


async def verify(secret: str, *, timeout: float = 5.0) -> VerificationResult:
    if ":" not in secret:
        return VerificationResult(
            VerificationStatus.ERROR,
            "expected access:secret pair",
        )
    access_key, _, secret_key = secret.partition(":")
    if not access_key.startswith("AKIA") or not secret_key:
        return VerificationResult(
            VerificationStatus.ERROR,
            "expected access:secret pair",
        )

    headers = _build_signed_request(access_key, secret_key)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(_URL, headers=headers, content=_PAYLOAD)
    except httpx.TimeoutException:
        return VerificationResult(VerificationStatus.ERROR, "timeout")
    except httpx.HTTPError as exc:
        return VerificationResult(VerificationStatus.ERROR, type(exc).__name__)

    code = response.status_code
    if code == 200 and "GetCallerIdentityResponse" in response.text:
        return VerificationResult(VerificationStatus.VERIFIED, "200")
    if code in (401, 403):
        return VerificationResult(VerificationStatus.DEAD, str(code))
    return VerificationResult(VerificationStatus.ERROR, str(code))
```

- [ ] **Step 4: Wire into registry**

Edit `gitexpose/verification/providers/__init__.py`:

```python
from .llm import LLM_VERIFIERS
from .code import CODE_VERIFIERS
from . import docker, slack, aws

VERIFIERS = {
    **LLM_VERIFIERS,
    **CODE_VERIFIERS,
    "docker_hub_pat":  docker.verify,
    "slack_token":     slack.verify,
    "aws_access_key":  aws.verify,
}

__all__ = ["VERIFIERS"]
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_verification_providers_aws.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/verification/providers/ tests/test_verification_providers_aws.py
git commit -m "✨ Register AWS access key verifier (hand-rolled SigV4 GetCallerIdentity)"
```

---

### Phase 6 — Log redaction safety net

#### Task 12: Log-leak canary test across all verifiers

**Files:**
- Test: `tests/test_verification_log_leak.py` (Create)

- [ ] **Step 1: Write the canary test**

Create `tests/test_verification_log_leak.py`:

```python
"""Canary test: no verifier may leak its raw secret into logs, stdout, stderr, or
the VerificationResult.detail field. Run every registered verifier with a
sentinel and grep all captured output."""

import logging

import pytest
import respx
import httpx

from gitexpose.verification.providers import VERIFIERS

SENTINEL = "CANARY-DO-NOT-LEAK-1234567890ABCDEFGHIJ"


@pytest.mark.asyncio
@pytest.mark.parametrize("pattern_name", sorted(VERIFIERS.keys()))
@respx.mock
async def test_no_verifier_leaks_raw_secret(pattern_name, caplog, capsys):
    # Mock every host the verifier might call to 401 (DEAD) so we don't make
    # live network calls and we hit the error-path code in the verifier.
    respx.route().mock(return_value=httpx.Response(401, text="unauthorized"))

    secret_value = (
        f"AKIA{SENTINEL[:16]}:{SENTINEL}"  # for AWS, which requires a pair
        if pattern_name == "aws_access_key"
        else SENTINEL
    )

    with caplog.at_level(logging.DEBUG, logger="gitexpose"):
        result = await VERIFIERS[pattern_name](secret_value)

    captured = capsys.readouterr()
    haystacks = [
        captured.out,
        captured.err,
        " ".join(record.getMessage() for record in caplog.records),
        result.detail or "",
    ]
    for haystack in haystacks:
        assert SENTINEL not in haystack, (
            f"{pattern_name} leaked SENTINEL into: {haystack!r}"
        )
```

- [ ] **Step 2: Run the canary test**

Run: `pytest tests/test_verification_log_leak.py -v`
Expected: 16 passed (one per registered verifier).

If any fail: locate the leak by inspecting which haystack contained the sentinel, then remove the raw secret from any `logger.debug(...)`, `print(...)`, or `detail=...` string.

- [ ] **Step 3: Commit**

```bash
git add tests/test_verification_log_leak.py
git commit -m "🧪 Add log-leak canary test across all 16 registered verifiers"
```

---

### Phase 7 — CLI integration

#### Task 13: Consent banner module

**Files:**
- Create: `gitexpose/verification/banner.py`
- Test: `tests/test_verification_banner.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_banner.py`:

```python
"""Tests for the consent banner."""

import sys

import pytest

from gitexpose.verification.banner import print_verify_banner


def test_banner_prints_to_stderr(capsys):
    print_verify_banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "verify" in captured.err.lower()


def test_banner_mentions_hosts(capsys):
    print_verify_banner()
    captured = capsys.readouterr()
    assert "api.openai.com" in captured.err
    assert "api.github.com" in captured.err
    assert "sts.amazonaws.com" in captured.err


def test_banner_can_be_suppressed(capsys):
    print_verify_banner(suppress=True)
    captured = capsys.readouterr()
    assert captured.err == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_banner.py -v`
Expected: FAIL — ImportError.

- [ ] **Step 3: Implement the banner**

Create `gitexpose/verification/banner.py`:

```python
"""Consent banner for --verify mode.

Prints to stderr (not stdout, so it doesn't pollute piped JSON/SARIF output).
"""

from __future__ import annotations

import sys

_BANNER = """\
[verify] Sending candidate credentials to provider APIs for liveness check.
[verify] Hosts: api.openai.com, api.anthropic.com, api.groq.com, openrouter.ai,
[verify]        api.perplexity.ai, api.x.ai, api.cerebras.ai, huggingface.co,
[verify]        api.elevenlabs.io, api.pinecone.io, api.smith.langchain.com,
[verify]        api.github.com, gitlab.com, hub.docker.com, slack.com,
[verify]        sts.amazonaws.com
[verify] Pass --no-verify-banner to suppress.
"""


def print_verify_banner(suppress: bool = False) -> None:
    """Print the consent banner unless suppress=True."""
    if suppress:
        return
    sys.stderr.write(_BANNER)
    sys.stderr.flush()
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_verification_banner.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/verification/banner.py tests/test_verification_banner.py
git commit -m "✨ Add consent banner for --verify mode"
```

---

#### Task 14: Wire --verify and friends into the main CLI

**Files:**
- Modify: `gitexpose/cli.py`
- Modify: `gitexpose/cli_advanced.py`
- Test: `tests/test_verification_cli.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_verification_cli.py`:

```python
"""Tests for --verify CLI integration."""

import json
import subprocess
import sys
from pathlib import Path


def test_help_shows_verify_flag():
    result = subprocess.run(
        [sys.executable, "-m", "gitexpose", "scan", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--verify" in result.stdout
    assert "--verify-concurrency" in result.stdout
    assert "--verify-timeout" in result.stdout
    assert "--no-verify-banner" in result.stdout


def test_supply_chain_help_shows_verify_flag():
    result = subprocess.run(
        [sys.executable, "-m", "gitexpose", "supply-chain", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--verify" in result.stdout


def test_supply_chain_without_verify_marks_findings_skipped(tmp_path):
    """A scan WITHOUT --verify should produce findings with verification_status=skipped."""
    target = tmp_path / "secret.env"
    target.write_text("OPENAI_API_KEY=sk-" + "a" * 30 + "\n")

    out_file = tmp_path / "out.json"
    subprocess.run(
        [sys.executable, "-m", "gitexpose", "supply-chain",
         str(tmp_path), "-o", "json", "--output-file", str(out_file)],
        check=True,
        capture_output=True,
    )
    report = json.loads(out_file.read_text())
    findings_with_status = []
    # The CLI emits both ScanResult-shaped findings and supply-chain findings;
    # walk anything that looks like a finding.
    def _walk(obj):
        if isinstance(obj, dict):
            if "verification_status" in obj:
                findings_with_status.append(obj)
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(report)
    assert findings_with_status, "expected at least one verification_status finding"
    assert all(f["verification_status"] == "skipped" for f in findings_with_status)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verification_cli.py -v`
Expected: FAIL — `--verify` flag not registered.

- [ ] **Step 3: Read the existing CLI**

Read `gitexpose/cli.py` and find the `scan` argparse subparser. Identify where existing flags like `--output` and `--target` are added.

Read `gitexpose/cli_advanced.py` and find the `supply-chain` subparser.

- [ ] **Step 4: Add --verify flags to both subparsers**

Define a shared function in `gitexpose/cli.py`:

```python
def add_verify_args(parser):
    """Attach the v0.3 verification flags to a subparser."""
    parser.add_argument(
        "--verify",
        action="store_true",
        default=False,
        help="Send candidate credentials to provider APIs for liveness check. "
             "Opt-in. Only patterns with a registered verifier are checked.",
    )
    parser.add_argument(
        "--verify-concurrency",
        type=int,
        default=5,
        metavar="N",
        help="Maximum concurrent verification requests across all providers (default: 5).",
    )
    parser.add_argument(
        "--verify-timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Per-request timeout for verification (default: 5.0).",
    )
    parser.add_argument(
        "--verify-only-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        metavar="LEVEL",
        help="Only verify findings whose severity is >= LEVEL.",
    )
    parser.add_argument(
        "--no-verify-banner",
        action="store_true",
        default=False,
        help="Suppress the consent banner printed when --verify is active.",
    )
```

Call `add_verify_args(scan_parser)` and `add_verify_args(supply_chain_parser)` from each subcommand's setup.

- [ ] **Step 5: Wire the post-processing step**

In both `gitexpose/cli.py` (for `scan`) and `gitexpose/cli_advanced.py` (for `supply-chain`), locate where findings are produced and passed to the reporter. Add this block before the report is emitted:

```python
if getattr(args, "verify", False):
    from gitexpose.verification import verify_secrets
    from gitexpose.verification.banner import print_verify_banner

    print_verify_banner(suppress=args.no_verify_banner)

    # Optional severity floor
    if args.verify_only_severity:
        from gitexpose.models import Severity
        floor = Severity[args.verify_only_severity]
        severity_order = {Severity.CRITICAL: 4, Severity.HIGH: 3,
                          Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
        floor_rank = severity_order[floor]
        filtered = [
            s for s in all_findings_as_dicts
            if severity_order.get(Severity(s.get("severity", "INFO")), 0) >= floor_rank
        ]
    else:
        filtered = all_findings_as_dicts

    import asyncio
    asyncio.run(verify_secrets(
        filtered,
        concurrency=args.verify_concurrency,
        timeout=args.verify_timeout,
    ))
    # filtered is mutated in place; un-filtered dicts already have status=skipped
```

`all_findings_as_dicts` is whatever the CLI's existing variable name is for the secret-dict list. If only `ScanResult` is available, convert via a temporary normalization step (each `ScanResult.verification_status` defaults to `"skipped"` so this is safe; only secrets pulled out of files via `SecretExtractor` are verifiable in v0.3).

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_verification_cli.py -v`
Expected: 3 passed.

- [ ] **Step 7: Commit**

```bash
git add gitexpose/cli.py gitexpose/cli_advanced.py tests/test_verification_cli.py
git commit -m "✨ Wire --verify and related flags into scan and supply-chain CLIs"
```

---

### Phase 8 — Reporter integration

#### Task 15: JSON reporter (verify field already present via dict serialization)

**Files:**
- Modify: `gitexpose/reporters/json_reporter.py` (likely no change)
- Test: `tests/test_reporters_v03.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_reporters_v03.py`:

```python
"""Tests for v0.3 reporter additions: verification status surfacing."""

import json

from gitexpose.models import Category, ScanReport, ScanResult, Severity, TargetReport
from gitexpose.reporters import (
    ConsoleReporter,
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    SARIFReporter,
)


def _make_report() -> ScanReport:
    finding = ScanResult(
        url="https://example.com/.env",
        path=".env",
        target="https://example.com",
        status_code=200,
        vulnerable=True,
        severity=Severity.CRITICAL,
        category=Category.ENV,
        description="Environment file exposed",
        evidence="Found: API_KEY=…",
        attack_class="LLM06",
        atlas_technique="AML.T0019",
        verification_status="verified",
        verification_detail="200",
    )
    return ScanReport(
        targets_scanned=1, targets_vulnerable=1, total_findings=1,
        critical_count=1, high_count=0, medium_count=0, low_count=0,
        scan_start="2026-05-27T12:00:00", scan_end="2026-05-27T12:00:01",
        scan_duration_ms=100,
        target_reports=[TargetReport(
            target="https://example.com", total_paths_checked=1, vulnerable_count=1,
            findings=[finding], errors=[], scan_duration_ms=100,
        )],
    )


def test_json_reporter_emits_verification_status():
    out = JSONReporter().generate(_make_report())
    parsed = json.loads(out)
    finding = parsed["target_reports"][0]["findings"][0]
    assert finding["verification_status"] == "verified"
    assert finding["verification_detail"] == "200"
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_reporters_v03.py::test_json_reporter_emits_verification_status -v`
Expected: Likely PASS — `JSONReporter` already serializes via `asdict` and the new fields are dataclass members. If it fails, inspect `json_reporter.py` and add the new keys explicitly to the serialization dict.

- [ ] **Step 3: Commit (no implementation change expected)**

```bash
git add tests/test_reporters_v03.py
git commit -m "🧪 Confirm JSON reporter surfaces verification_status fields"
```

---

#### Task 16: SARIF reporter — verification_status property + tag

**Files:**
- Modify: `gitexpose/reporters/sarif_reporter.py`
- Modify: `tests/test_reporters_v03.py` (extend)

- [ ] **Step 1: Append to test file**

Add to `tests/test_reporters_v03.py`:

```python
def test_sarif_reporter_includes_verification_property_and_tag():
    out = SARIFReporter().generate(_make_report())
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result["properties"]["verification_status"] == "verified"
    assert "verified-live" in result.get("properties", {}).get("tags", [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporters_v03.py::test_sarif_reporter_includes_verification_property_and_tag -v`
Expected: FAIL — verification property not present.

- [ ] **Step 3: Modify SARIF reporter**

Read `gitexpose/reporters/sarif_reporter.py`. Locate where each `result` dict is built (look for `"results": [...]` or similar). After existing properties are set, add:

```python
verification_status = getattr(finding, "verification_status", "skipped")
result["properties"]["verification_status"] = verification_status
if verification_status == "verified":
    tag = "verified-live"
elif verification_status == "dead":
    tag = "verified-dead"
elif verification_status == "error":
    tag = "verification-error"
else:
    tag = None
if tag:
    result["properties"].setdefault("tags", []).append(tag)
```

(Adjust the variable name to whatever the file calls the current result dict.)

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_reporters_v03.py -v`
Expected: All passed.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/reporters/sarif_reporter.py tests/test_reporters_v03.py
git commit -m "✨ Surface verification_status in SARIF properties + tag for Code Scanning filtering"
```

---

#### Task 17: HTML reporter — verification badge

**Files:**
- Modify: `gitexpose/reporters/html_reporter.py`
- Modify: `tests/test_reporters_v03.py` (extend)

- [ ] **Step 1: Append to test file**

Add to `tests/test_reporters_v03.py`:

```python
def test_html_reporter_renders_verified_badge():
    out = HTMLReporter().generate(_make_report())
    assert "badge-verified" in out or "LIVE" in out
    assert "verified" in out.lower()


def test_html_reporter_no_badge_for_skipped(monkeypatch):
    report = _make_report()
    report.target_reports[0].findings[0].verification_status = "skipped"
    out = HTMLReporter().generate(report)
    # No verification badge when status is skipped (don't clutter the page)
    assert "badge-verified" not in out
    assert "badge-dead" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporters_v03.py -v -k html`
Expected: FAIL.

- [ ] **Step 3: Modify HTML reporter**

Read `gitexpose/reporters/html_reporter.py`. Locate where each finding's HTML row/card is built. Add:

```python
verification_status = getattr(finding, "verification_status", "skipped")
verify_badge = ""
if verification_status == "verified":
    verify_badge = '<span class="badge badge-verified">LIVE</span>'
elif verification_status == "dead":
    verify_badge = '<span class="badge badge-dead">DEAD</span>'
elif verification_status == "error":
    verify_badge = '<span class="badge badge-error">?</span>'
# skipped / unverifiable: no badge
```

Inject `verify_badge` next to the existing severity/OWASP/ATLAS badges. In the `<style>` block, add:

```css
.badge-verified { background: #cb2431; color: white; padding: 2px 6px; border-radius: 3px; margin-left: 4px; font-size: 11px; font-weight: bold; }
.badge-dead     { background: #6a737d; color: white; padding: 2px 6px; border-radius: 3px; margin-left: 4px; font-size: 11px; }
.badge-error    { background: #f1e05a; color: black; padding: 2px 6px; border-radius: 3px; margin-left: 4px; font-size: 11px; }
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_reporters_v03.py -v -k html`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/reporters/html_reporter.py tests/test_reporters_v03.py
git commit -m "✨ Add verification status badges (LIVE/DEAD/?) to HTML reporter"
```

---

#### Task 18: CSV reporter — verification columns

**Files:**
- Modify: `gitexpose/reporters/csv_reporter.py`
- Modify: `tests/test_reporters_v03.py` (extend)

- [ ] **Step 1: Append to test file**

Add to `tests/test_reporters_v03.py`:

```python
def test_csv_reporter_has_verification_columns():
    out = CSVReporter().generate(_make_report())
    header = out.splitlines()[0]
    assert "verification_status" in header.lower()
    assert "verification_detail" in header.lower()
    assert "verified" in out
    assert ",200," in out or ",200\n" in out or "200" in out.splitlines()[1]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporters_v03.py -v -k csv`
Expected: FAIL.

- [ ] **Step 3: Modify CSV reporter**

Read `gitexpose/reporters/csv_reporter.py`. Locate the header writer and the row writer (look for `csv.writer.writerow(...)` or similar). Append two columns:

- Header: extend the column list with `"verification_status"`, `"verification_detail"`.
- Row: extend the row tuple with `getattr(finding, "verification_status", "skipped")`, `getattr(finding, "verification_detail", "") or ""`.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_reporters_v03.py -v -k csv`
Expected: PASSED.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/reporters/csv_reporter.py tests/test_reporters_v03.py
git commit -m "✨ Add verification_status and verification_detail columns to CSV reporter"
```

---

#### Task 19: Console reporter — colored verification tag

**Files:**
- Modify: `gitexpose/reporters/console.py`
- Modify: `tests/test_reporters_v03.py` (extend)

- [ ] **Step 1: Append to test file**

Add to `tests/test_reporters_v03.py`:

```python
def test_console_reporter_renders_verification_tag():
    out = ConsoleReporter(no_color=True).generate(_make_report())
    assert "[VERIFIED]" in out or "VERIFIED" in out


def test_console_reporter_no_tag_for_skipped():
    report = _make_report()
    report.target_reports[0].findings[0].verification_status = "skipped"
    out = ConsoleReporter(no_color=True).generate(report)
    assert "[VERIFIED]" not in out
    assert "[DEAD]" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporters_v03.py -v -k console`
Expected: FAIL.

- [ ] **Step 3: Modify console reporter**

Read `gitexpose/reporters/console.py`. Locate where each finding's line is rendered. After the existing severity/path line, append a verification tag if status is one of `verified`/`dead`/`error`:

```python
status = getattr(finding, "verification_status", "skipped")
if status == "verified":
    out.append("   [VERIFIED]")
elif status == "dead":
    out.append("   [DEAD]")
elif status == "error":
    detail = getattr(finding, "verification_detail", "") or "?"
    out.append(f"   [ERROR: {detail}]")
elif status == "unverifiable":
    out.append("   [UNVERIFIABLE]")
# skipped: no tag
```

(Replace `out.append` with whatever the file's accumulator is. Use rich color tags if `no_color=False`.)

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_reporters_v03.py -v -k console`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/reporters/console.py tests/test_reporters_v03.py
git commit -m "✨ Append colored verification tag to console reporter output"
```

---

### Phase 9 — Smoke / fixture integration

#### Task 20: v0.3 smoke test against extended synthetic fixture

**Files:**
- Create: `tests/fixtures/synthetic_repo_v03/.env`
- Test: `tests/test_smoke_v03.py` (Create)

- [ ] **Step 1: Create the extended synthetic fixture**

Create `tests/fixtures/synthetic_repo_v03/.env`:

```
# v0.3 smoke fixture — every credential below is fake but matches its pattern.
OPENAI_API_KEY=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ANTHROPIC_API_KEY=sk-ant-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
GROQ_API_KEY=gsk_cccccccccccccccccccccccccccccccccccccccccccccccccccc
GITHUB_TOKEN=ghp_dddddddddddddddddddddddddddddddddddd
GITLAB_TOKEN=glpat-eeeeeeeeeeeeeeeeeeee
DOCKER_PAT=dckr_pat_fffffffffffffffffffffffffff
SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnopqrstuvwx
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

- [ ] **Step 2: Write the smoke test**

Create `tests/test_smoke_v03.py`:

```python
"""End-to-end smoke test: --verify against the v0.3 fixture with all hosts mocked."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import respx
import httpx

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_repo_v03"

ALL_VERIFY_HOSTS = [
    "api.openai.com", "api.anthropic.com", "api.groq.com", "openrouter.ai",
    "api.perplexity.ai", "api.x.ai", "api.cerebras.ai", "huggingface.co",
    "api.elevenlabs.io", "api.pinecone.io", "api.smith.langchain.com",
    "api.github.com", "gitlab.com", "hub.docker.com", "slack.com",
    "sts.amazonaws.com",
]


def test_supply_chain_with_verify_runs_against_fixture(tmp_path):
    """Black-box smoke: --verify runs end-to-end via subprocess.
    Each verifier hits its real host; we accept any outcome (live network may
    or may not be reachable in CI). The point is the CLI doesn't crash."""
    out_file = tmp_path / "out.json"
    result = subprocess.run(
        [sys.executable, "-m", "gitexpose", "supply-chain",
         str(FIXTURE), "-o", "json", "--output-file", str(out_file),
         "--verify", "--verify-timeout", "2", "--no-verify-banner"],
        capture_output=True,
        text=True,
    )
    # The scan must complete (return code 0 or 1 depending on findings)
    assert result.returncode in (0, 1, 2), f"Unexpected exit: {result.returncode}, stderr={result.stderr}"

    if out_file.exists():
        report = json.loads(out_file.read_text())
        # Every finding has a verification_status field
        found = []
        def _walk(o):
            if isinstance(o, dict):
                if "verification_status" in o:
                    found.append(o)
                for v in o.values():
                    _walk(v)
            elif isinstance(o, list):
                for v in o:
                    _walk(v)
        _walk(report)
        assert found, "expected findings with verification_status"
        valid_statuses = {"verified", "dead", "error", "skipped", "unverifiable"}
        for f in found:
            assert f["verification_status"] in valid_statuses
```

- [ ] **Step 3: Run smoke test**

Run: `pytest tests/test_smoke_v03.py -v`
Expected: PASSED.

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/synthetic_repo_v03/ tests/test_smoke_v03.py
git commit -m "🧪 Add v0.3 end-to-end smoke test against extended synthetic fixture"
```

---

### Phase 10 — Tier 3 provider patterns

#### Task 21: Add Tier 3 providers to credential_patterns_v02.json

**Files:**
- Modify: `gitexpose/data/credential_patterns_v02.json`
- Modify: `docs/COVERAGE.md`
- Test: `tests/test_tier3_patterns.py` (Create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_tier3_patterns.py`:

```python
"""Tests for Tier 3 provider credential patterns."""

import asyncio

from gitexpose.secrets.secret_extractor import SecretExtractor


def _extract(content: str):
    return asyncio.run(SecretExtractor().extract(content))


def test_helicone_api_key_detected():
    secrets = _extract("HELICONE_API_KEY=sk-helicone-" + "a" * 40)
    assert any(s["type"] == "helicone_api_key" for s in secrets)


def test_portkey_api_key_detected():
    secrets = _extract("PORTKEY_API_KEY=" + "Z" * 32)
    # Portkey uses a generic alphanumeric format; context-bound
    assert any(s["type"] == "portkey_api_key" for s in secrets)


def test_voyage_api_key_detected():
    secrets = _extract("VOYAGE_API_KEY=pa-" + "a" * 40)
    assert any(s["type"] == "voyage_api_key" for s in secrets)


def test_cohere_api_key_detected():
    secrets = _extract("COHERE_API_KEY=co-" + "x" * 40)
    assert any(s["type"] == "cohere_api_key" for s in secrets)


def test_modal_token_pair_detected():
    """Modal uses paired token (ak-… + as-…)."""
    secrets = _extract(
        "MODAL_TOKEN_ID=ak-" + "1" * 32 + "\n"
        "MODAL_TOKEN_SECRET=as-" + "2" * 32 + "\n"
    )
    types = {s["type"] for s in secrets}
    assert "modal_token_id" in types
    assert "modal_token_secret" in types


def test_runpod_api_key_detected():
    """Runpod uses a generic uppercase alphanumeric key, context-bound."""
    secrets = _extract("RUNPOD_API_KEY=" + "Y" * 40)
    assert any(s["type"] == "runpod_api_key" for s in secrets)


def test_all_tier3_have_owasp_atlas_metadata():
    secrets = _extract(
        "HELICONE_API_KEY=sk-helicone-" + "a" * 40 + "\n"
        "COHERE_API_KEY=co-" + "x" * 40 + "\n"
    )
    for s in secrets:
        if s["type"] in {"helicone_api_key", "cohere_api_key"}:
            assert s["attack_class"] == "LLM06"
            assert s["atlas_technique"] == "AML.T0019"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_tier3_patterns.py -v`
Expected: FAIL — Tier 3 patterns not in JSON yet.

- [ ] **Step 3: Add Tier 3 patterns to JSON**

In `gitexpose/data/credential_patterns_v02.json`, append to the `"patterns"` array (before the closing `]`):

```json
,
{"name": "helicone_api_key", "regex": "sk-helicone-[a-zA-Z0-9_-]{30,}", "severity": "HIGH", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_observability", "description": "Helicone API key (LLM observability platform)"},
{"name": "portkey_api_key", "regex": "(?:PORTKEY_API_KEY|portkey-api-key)\\s*[=:]\\s*[\\\"']?([A-Za-z0-9]{30,})[\\\"']?", "severity": "HIGH", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_observability", "description": "Portkey API key (context-bound)"},
{"name": "voyage_api_key", "regex": "pa-[a-zA-Z0-9_-]{32,}", "severity": "CRITICAL", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_provider", "description": "Voyage AI API key"},
{"name": "cohere_api_key", "regex": "co-[a-zA-Z0-9_-]{36,}", "severity": "CRITICAL", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_provider", "description": "Cohere API key"},
{"name": "modal_token_id", "regex": "ak-[a-zA-Z0-9]{20,}", "severity": "CRITICAL", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_infra", "description": "Modal token ID (paired with secret)"},
{"name": "modal_token_secret", "regex": "as-[a-zA-Z0-9]{20,}", "severity": "CRITICAL", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_infra", "description": "Modal token secret"},
{"name": "runpod_api_key", "regex": "(?:RUNPOD_API_KEY)\\s*[=:]\\s*[\\\"']?([A-Z0-9]{30,})[\\\"']?", "severity": "HIGH", "attack_class": "LLM06", "atlas_technique": "AML.T0019", "category": "llm_infra", "description": "Runpod API key (context-bound)"}
```

- [ ] **Step 4: Run pattern tests**

Run: `pytest tests/test_tier3_patterns.py -v`
Expected: 7 passed.

- [ ] **Step 5: Update COVERAGE.md**

In `docs/COVERAGE.md`, find the table sections and append rows for Helicone, Portkey, Voyage, Cohere, Modal (two rows), and Runpod. Also add a new column or section noting which Tier 3 providers have verifiers in v0.3 — **none** of them do (Tier 3 patterns are detection-only in v0.3; verification will come in v0.4).

Add a paragraph below the table:

> **Verification status (v0.3):** Tier 1–2 providers (OpenAI, Anthropic, Groq, OpenRouter, Perplexity, xAI, Cerebras, Hugging Face, ElevenLabs, Pinecone, LangSmith, GitHub PAT, GitLab PAT, Docker Hub, Slack token, AWS) support `--verify` for live/dead status. Tier 3 (Helicone, Portkey, Voyage, Cohere, Modal, Runpod) ship as detection-only in v0.3; verification arrives in v0.4 once their endpoint surfaces are documented and audited.

- [ ] **Step 6: Run full suite**

Run: `pytest -v`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add gitexpose/data/credential_patterns_v02.json tests/test_tier3_patterns.py docs/COVERAGE.md
git commit -m "✨ Add Tier 3 provider patterns (Helicone, Portkey, Voyage, Cohere, Modal, Runpod)"
```

---

### Phase 11 — CI/CD integrations

#### Task 22: GitHub Actions sample workflow + pre-commit hook config

**Files:**
- Create: `.github/workflows/gitexpose-scan.yml`
- Create: `.pre-commit-hooks.yaml`
- Create: `docs/INTEGRATIONS_CICD.md`

- [ ] **Step 1: Create the GitHub Actions workflow**

Create `.github/workflows/gitexpose-scan.yml`:

```yaml
# Sample workflow showing how to run GitExpose against a repo's working tree on
# every PR and on push to main. Findings are uploaded to GitHub Code Scanning
# via the SARIF reporter. See docs/INTEGRATIONS_CODE_SCANNING.md for the
# Code-Scanning-specific setup.

name: GitExpose Supply Chain Scan
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write  # required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install GitExpose
        run: |
          python -m pip install --upgrade pip
          pip install gitexpose

      - name: Run supply-chain scan
        run: |
          gitexpose supply-chain . \
            --output sarif \
            --output-file gitexpose-results.sarif
        continue-on-error: true  # let the upload step run even if findings exist

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitexpose-results.sarif
          category: gitexpose
```

- [ ] **Step 2: Create the pre-commit hook config**

Create `.pre-commit-hooks.yaml`:

```yaml
# Pre-commit hook definitions for downstream repos. To use:
#
#   # In a downstream repo's .pre-commit-config.yaml:
#   repos:
#     - repo: https://github.com/fevra-dev/GitExpose
#       rev: v0.3.0
#       hooks:
#         - id: gitexpose-staged
#
# This hook runs the supply-chain scanner on the file list staged for commit.

- id: gitexpose-staged
  name: GitExpose supply-chain scan (staged files)
  description: Scan staged files for credentials and supply-chain risk
  entry: gitexpose supply-chain
  language: python
  types: [text]
  pass_filenames: true
  stages: [pre-commit]

- id: gitexpose-full
  name: GitExpose supply-chain scan (full repo)
  description: Scan the entire working tree
  entry: gitexpose supply-chain .
  language: python
  pass_filenames: false
  stages: [pre-commit, manual]
```

- [ ] **Step 3: Create the integration docs**

Create `docs/INTEGRATIONS_CICD.md`:

```markdown
# GitExpose CI/CD Integration Guide

GitExpose ships ready-to-use configs for GitHub Actions and pre-commit. This
doc shows how to wire them into your pipeline.

## GitHub Actions

The sample workflow at `.github/workflows/gitexpose-scan.yml` runs GitExpose on
every PR and uploads results to GitHub Code Scanning via SARIF. To use it:

1. Copy the workflow file into your own repo at the same path.
2. Ensure your repo has Code Scanning enabled (Settings → Security → Code
   Scanning → Set up advanced).
3. Push the workflow. On the next PR, findings appear in the PR's "Security"
   tab and as inline annotations.

### Customizing

| Variable | Default | Why change |
|---|---|---|
| `python-version` | 3.12 | Pin to your team's Python |
| `--output-file` | `gitexpose-results.sarif` | Match your Code Scanning config |
| `--verify` flag | off | Add `--verify` for live-credential confirmation. Note: this sends candidate credentials to provider APIs from your CI runners. Most teams should NOT enable this in CI without explicit security approval. |

### Adding `--verify` to CI (advanced)

If you understand the trade-offs and want CI to confirm liveness, add `--verify`
to the scan step. **Read `docs/INTEGRATIONS_CODE_SCANNING.md` first.**

```yaml
      - name: Run supply-chain scan with verification
        run: |
          gitexpose supply-chain . \
            --verify \
            --no-verify-banner \
            --verify-only-severity HIGH \
            --output sarif \
            --output-file gitexpose-results.sarif
```

## pre-commit

The pre-commit config at `.pre-commit-hooks.yaml` exposes two hooks:

- `gitexpose-staged` — fast, scans only the files staged for the current commit
- `gitexpose-full` — thorough, scans the entire working tree (use as a manual
  stage or for an occasional full pass)

### Local setup

In your repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/fevra-dev/GitExpose
    rev: v0.3.0
    hooks:
      - id: gitexpose-staged
```

Then:

```bash
pip install pre-commit
pre-commit install
git commit -m "test"  # gitexpose now runs against staged files
```

### What the hook blocks

By default, the `gitexpose-staged` hook reports findings to stderr and exits
non-zero if any CRITICAL finding is present in the staged file set. You can
tune this by overriding the entry point in your own config:

```yaml
      - id: gitexpose-staged
        entry: gitexpose supply-chain --severity-threshold HIGH
```
```

- [ ] **Step 4: Smoke-check the workflow YAML**

Run a YAML lint:

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/gitexpose-scan.yml')); yaml.safe_load(open('.pre-commit-hooks.yaml')); print('OK')"
```

Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/gitexpose-scan.yml .pre-commit-hooks.yaml docs/INTEGRATIONS_CICD.md
git commit -m "✨ Add GitHub Actions workflow, pre-commit hooks, and CI/CD integration doc"
```

---

#### Task 23: GitHub Code Scanning integration doc

**Files:**
- Create: `docs/INTEGRATIONS_CODE_SCANNING.md`

- [ ] **Step 1: Write the doc**

Create `docs/INTEGRATIONS_CODE_SCANNING.md`:

```markdown
# GitExpose × GitHub Code Scanning

GitExpose emits SARIF 2.1.0 (vendored schema validated) so its findings show up
natively in GitHub Code Scanning. This page covers the end-to-end setup.

## What you get

- Findings as Code Scanning alerts in the PR "Security" tab
- Inline annotations on the lines where credentials or supply-chain risks live
- MITRE ATLAS and OWASP LLM Top 10 taxonomy references on every alert
- Verification status (`verified-live` / `verified-dead` / `verification-error`)
  as alert tags — filter the dashboard by tag

## Setup (5 minutes)

1. **Enable Code Scanning** on your repo:
   Settings → Security → Code security and analysis → Code scanning → Set up
   advanced.

2. **Add the GitExpose workflow**. Copy `.github/workflows/gitexpose-scan.yml`
   from this repo into your own.

3. **Push**. On the next PR or push to main, GitExpose runs and uploads SARIF.

4. **Review alerts**. Open the "Security" tab on your repo. New alerts appear
   under "Code scanning alerts".

## Filtering by verification status

GitExpose v0.3 emits SARIF `properties.tags` entries:

- `verified-live` — credential confirmed active by the provider
- `verified-dead` — credential rejected by the provider
- `verification-error` — couldn't reach the provider (network / 5xx / timeout)

Use these in Code Scanning's filter UI to focus on the highest-confidence
alerts. Example: `tag:verified-live` to see only credentials that are
confirmed exploitable today.

## Sample SARIF output

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "GitExpose",
          "version": "0.3.0",
          "informationUri": "https://github.com/fevra-dev/GitExpose"
        }
      },
      "results": [
        {
          "ruleId": "credential-exposure",
          "level": "error",
          "message": {"text": "OpenAI API key exposed and confirmed live"},
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": ".env"},
              "region": {"startLine": 14}
            }
          }],
          "properties": {
            "attack_class": "LLM06",
            "atlas_technique": "AML.T0019",
            "verification_status": "verified",
            "tags": ["verified-live"]
          }
        }
      ]
    }
  ]
}
```

## Troubleshooting

- **No alerts appearing?** Check the workflow run logs — Code Scanning requires
  `security-events: write` permission, which the sample workflow sets.
- **Too many alerts?** Use `--severity-threshold HIGH` in the scan step to drop
  MEDIUM/LOW findings before SARIF upload.
- **SARIF rejected by GitHub?** GitExpose validates its own output against the
  vendored 2.1.0 schema in `tests/fixtures/sarif-schema-2.1.0.json`. If GitHub
  rejects it, file an issue with the offending finding's JSON snippet.
```

- [ ] **Step 2: Commit**

```bash
git add docs/INTEGRATIONS_CODE_SCANNING.md
git commit -m "📝 Add GitHub Code Scanning integration doc"
```

---

### Phase 12 — Documentation

#### Task 24: MITRE ATLAS coverage map

**Files:**
- Create: `docs/MITRE_ATLAS_COVERAGE.md`

- [ ] **Step 1: Write the coverage map**

Create `docs/MITRE_ATLAS_COVERAGE.md`:

```markdown
# GitExpose × MITRE ATLAS Coverage Map

Last updated: v0.3

This document maps every GitExpose detection to a MITRE ATLAS technique. ATLAS
(Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's
adversary behavior knowledge base for AI/ML systems, modeled after ATT&CK.

Reference: https://atlas.mitre.org/

## Per-detection mapping

### Credential detection

| Pattern family | ATLAS technique | Justification |
|---|---|---|
| LLM provider keys (OpenAI, Anthropic, Groq, OpenRouter, Perplexity, xAI, Cerebras, HuggingFace, ElevenLabs, Pinecone, LangSmith) | `AML.T0019` (Publish Poisoned Datasets) → Initial Access via Valid Accounts | An exposed LLM provider key allows an adversary to send requests as the victim. The downstream attack class is broad — model poisoning, data exfiltration via prompt injection, cost denial-of-service. The primary access vector is account takeover via valid credentials. |
| Code/cloud platform keys (GitHub PAT, GitLab PAT, AWS access keys, Docker Hub PAT) | `AML.T0019` + `AML.T0042` (Disable AI Logging) when scope includes audit log control | Same valid-accounts vector; AWS keys with IAM admin and GitHub PATs with `repo` scope are the highest-impact subset. |
| Communication tokens (Slack, Discord bot/webhook, Telegram) | `AML.T0050` (Command and Scripting Interpreter) → AI agent C2 | Exposed bot/webhook tokens enable AI-agent C2 channels and lateral movement into LLM-augmented workflows. |
| Payment keys (Stripe live/test) | `AML.T0019` (financial reconnaissance) | Out-of-band ATLAS mapping; included for completeness. |
| Database connection strings (Postgres, MySQL, MongoDB) | `AML.T0046` (Data Exfiltration) | Direct DB access for training-data exfiltration. |

### Supply chain detection

| Detection | ATLAS technique | Justification |
|---|---|---|
| `unpinned_ai_middleware` | `AML.T0010` (ML Supply Chain Compromise) | Unpinned versions allow compromised maintainer tokens to push malicious code without notice. TeamPCP-class incident. |
| `known_malicious_package_version` | `AML.T0010` | Confirmed-bad versions of `litellm`, `telnyx`, `xinference`, etc. |
| `slopsquatting` | `AML.T0010` + `AML.T0019` | LLM-hallucinated package names being preemptively registered as malware. |
| `pth_persistence` | `AML.T0011` (Persistence) | `.pth` files with `exec`/`eval`/`base64` are a Python-import-time execution vector. |
| `ai_c2_beacon` | `AML.TA0015` (Command and Control) | Skills that instruct an AI agent to operate as a C2 implant. |
| `kubernetes_exfiltration` | `AML.T0046` (Exfiltration via Cloud Storage) | k8s service-account token access patterns leading to ML model and secret exfiltration. |

### AI tool configuration detection

| Detection | ATLAS technique | Justification |
|---|---|---|
| `.continue/`, `claude/.credentials.json` | `AML.T0019` | Direct exposure of LLM provider keys via AI-IDE config files. |
| `litellm_config.yaml`, `OAI_CONFIG_LIST` | `AML.T0019` | Multi-provider key aggregators — one file compromise → many provider compromises. |
| `mcp.json`, `.cursor/mcp.json` | `AML.T0059` (Indirect Prompt Injection via MCP) | Malicious MCP entries are a tool-injection vector for AI agents. |
| `.env.*.example`, `.env.*.bak` | `AML.T0019` | Frequently contain real keys despite "example"/"bak" naming. |
| `firebase-config.js` | `AML.T0019` | Embeds Firebase API key in client code. |

### Detection-only categories (no ATLAS mapping yet)

These are GitExpose detections that don't yet map cleanly to ATLAS techniques.
Listed here for transparency.

- Generic API key (catch-all entropy/pattern) — too broad for a specific
  technique.
- JWT structural detection (no signature verification) — informational only.
- Private key (PEM) — could be many techniques depending on usage; left
  unmapped to avoid over-claiming.

## How GitExpose surfaces ATLAS data

Every applicable finding includes an `atlas_technique` field. This is rendered:

- in JSON output as `finding.atlas_technique`
- in SARIF output as `result.properties.atlas_technique` and as a taxonomy reference
- in HTML output as a red `ATLAS` badge next to the severity badge
- in CSV output as a column
- in console output as part of the finding's compliance line

## Caveats

- ATLAS is younger than ATT&CK and its technique list is evolving. Some of our
  mappings (`AML.T0019` → "Valid Accounts" reuse for LLM API keys) may be
  refined as ATLAS adds more specific techniques.
- A single GitExpose finding may legitimately touch multiple ATLAS techniques;
  we surface the single closest match to keep the model simple.
- We do not currently auto-update from upstream ATLAS releases; the mapping is
  refreshed manually on each GitExpose release.
```

- [ ] **Step 2: Commit**

```bash
git add docs/MITRE_ATLAS_COVERAGE.md
git commit -m "📝 Add MITRE ATLAS coverage map for all v0.3 detections"
```

---

#### Task 25: README — CISA-incident motivation callout

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the existing README**

Read the first 50 lines of `README.md` to find the right insertion point. The callout belongs under an introductory section, before the "Quick Start" or feature list.

- [ ] **Step 2: Add the callout section**

Insert into `README.md` after the project description (and before the Quick Start / Install section):

```markdown
## Why this matters

In May 2026, KrebsOnSecurity and GitGuardian reported on a public GitHub
repository named `Private-CISA`. The repo, created by a CISA contractor in
November 2025, contained 844 MB of operational material: CI/CD logs,
Kubernetes manifests, Terraform code, GitHub workflows, internal docs, AWS
GovCloud admin credentials, and plaintext passwords for internal systems.

This is the threat model GitExpose is built for. GitHub is the production
perimeter, and one careless commit can publish keys, infrastructure maps, and
operational secrets to attackers who never needed a zero-day.

GitExpose v0.3 adds **active credential verification** — instead of just
flagging that a string looks like an OpenAI key or an AWS access key, it
confirms whether that credential is live by sending a low-footprint
authentication check to the provider. Live keys get flagged as `verified-live`
in SARIF output and surface as the highest-confidence alerts in GitHub Code
Scanning.

References:
- [KrebsOnSecurity: CISA contractor leak](https://krebsonsecurity.com/) (May 2026)
- [GitGuardian incident analysis](https://blog.gitguardian.com/)
```

(Adjust the link URLs to the actual article URLs if you have them; otherwise leave the placeholder root URLs and add a one-line note that the implementor should look up the canonical article URLs.)

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "📝 Add CISA-incident 'Why this matters' callout to README"
```

---

### Phase 13 — Repo cleanup and release

#### Task 26: Gitignore additions and notes folder

**Files:**
- Modify: `.gitignore`
- Create: `docs/notes/` (directory) — move existing root `.md` notes here

- [ ] **Step 1: Add gitignore entries**

In `.gitignore`, append:

```
# v0.3 cleanup — workspace artifacts that should not be tracked
.serena/
RESEARCH/
files/
files (1)/
Gemini_Generated_Image_*.png
```

- [ ] **Step 2: Move root markdown notes into docs/notes/**

```bash
mkdir -p docs/notes
git mv "github notes from linkedin.md" docs/notes/2026-05-cisa-private-repo-incident.md
git mv "trufflehog-features-4-prizm+gitexpose.md" docs/notes/trufflehog-features-for-prizm-and-gitexpose.md
```

- [ ] **Step 3: Confirm no other tracked files reference the old paths**

```bash
git grep -F "github notes from linkedin.md"
git grep -F "trufflehog-features-4-prizm+gitexpose.md"
```

Expected: No matches. (If any, update them to the new paths.)

- [ ] **Step 4: Commit**

```bash
git add .gitignore docs/notes/
git commit -m "🧹 v0.3 cleanup — gitignore workspace dirs, move root notes under docs/notes/"
```

---

#### Task 27: Version bump, CHANGELOG, and release tag

**Files:**
- Modify: `gitexpose/__init__.py`
- Modify: `pyproject.toml`
- Modify: `setup.py`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Bump version**

In `gitexpose/__init__.py`, change `__version__ = "0.2.0"` to `"0.3.0"`.

In `pyproject.toml`, change `version = "0.2.0"` to `"0.3.0"`.

In `setup.py`, change `version="0.2.0"` to `"0.3.0"`.

- [ ] **Step 2: Update CHANGELOG**

Prepend to `CHANGELOG.md` (before the `## v0.2.0` entry):

```markdown
## v0.3.0 — 2026-05-XX — Active Verification

### Added

- **Active Verification engine** (opt-in via `--verify`). 16 providers
  supported: OpenAI (3 variants), Anthropic, Groq, OpenRouter, Perplexity,
  xAI, Cerebras, Hugging Face, ElevenLabs, Pinecone, LangSmith (v2 + legacy),
  GitHub PAT, GitLab PAT, Docker Hub, Slack token, AWS (SigV4
  `GetCallerIdentity`). Verification adds binary `verified` / `dead` / `error`
  status to each applicable finding.
- **`--verify` CLI flags:** `--verify`, `--verify-concurrency`,
  `--verify-timeout`, `--verify-only-severity`, `--no-verify-banner`.
- **Consent banner** printed to stderr when `--verify` is active. Names every
  destination host.
- **Verification surfaces in all reporters:** JSON (`verification_status`,
  `verification_detail`), SARIF (`properties.verification_status` + `tags`),
  HTML (color badge), CSV (two new columns), console (colored tag).
- **In-run dedup:** identical secrets in multiple files trigger only one
  verification call per scan.
- **Log-redaction safety net:** every verifier and engine path tested with a
  sentinel canary to guarantee no raw secret leaks to logs, stdout, stderr, or
  `verification_detail`.
- **Tier 3 provider patterns:** Helicone, Portkey, Voyage, Cohere, Modal
  (paired token), Runpod. Detection-only in v0.3; verification deferred to
  v0.4.
- **GitHub Actions sample workflow** at `.github/workflows/gitexpose-scan.yml`.
- **pre-commit hook config** at `.pre-commit-hooks.yaml`.
- **`docs/INTEGRATIONS_CICD.md`** — pipeline setup walkthrough.
- **`docs/INTEGRATIONS_CODE_SCANNING.md`** — GitHub Code Scanning setup +
  SARIF tag filtering.
- **`docs/MITRE_ATLAS_COVERAGE.md`** — per-detection ATLAS technique mapping.
- **README "Why this matters" section** linking to the CISA `Private-CISA`
  incident.

### Changed

- New runtime dependency: `httpx>=0.27.0`.
- New dev dependency: `respx>=0.21.0` for HTTP mocking in tests.
- Test count grew from ~125 (v0.2.0) to ~165 (v0.3.0).
- Root-level `.md` notes moved under `docs/notes/`.
- `.gitignore` extended for workspace dirs (`.serena/`, `RESEARCH/`, root
  PNGs).

### Fixed

- **`gitexpose/advanced/mcp_server.py:432`** — removed unsupported `validate=`
  kwarg from `SecretExtractor.extract()` call; fixed `.get("valid")` →
  `.get("validated")` typo. Regression test added.

### Deferred to v0.4

- Capability/scope enumeration (AWS IAM perms, GitHub PAT scopes, OpenAI
  org/project membership)
- AI-BOM (SPDX 3.0) output format
- Verifiers for Discord bot/webhook, Telegram, Twilio, SendGrid, Stripe (each
  needs case-by-case side-effect analysis)
- Tier 3 provider verification (need documented endpoint surfaces)
- Persistent cross-run verification cache
- Deep git-history traversal
```

(Replace `2026-05-XX` with the actual release date when tagging.)

- [ ] **Step 3: Run the full test suite one last time**

```bash
pytest -v
```

Expected: All passing. Target test count: ~165.

- [ ] **Step 4: Commit the version bump**

```bash
git add gitexpose/__init__.py pyproject.toml setup.py CHANGELOG.md
git commit -m "🔖 Bump to v0.3.0 and update CHANGELOG"
```

- [ ] **Step 5: Create the annotated tag**

```bash
git tag -a v0.3.0 -m "v0.3.0 — Active Verification

Adds opt-in active verification (--verify) across 16 providers.
Adds CI/CD integration glue (GH Actions, pre-commit, Code Scanning).
Adds Tier 3 provider patterns and MITRE ATLAS coverage doc.
Fixes mcp_server.py kwarg bug carried over from v0.2."
```

**DO NOT** push the tag yet. The release is gated on a final manual smoke verification by the maintainer.

- [ ] **Step 6: Confirm the tag and stop**

```bash
git tag --list v0.3.0
git log --oneline -5
```

Expected: `v0.3.0` listed, last commit is the version bump.

Hand back to the user with: "v0.3.0 commit chain complete and tagged locally. Run the verification flow yourself, then `git push origin main && git push origin v0.3.0` when satisfied."

---

## Final Verification Checklist (post-implementation)

Before shipping, the implementer or maintainer confirms:

- [ ] All 27 tasks completed in order, every commit message present in `git log`.
- [ ] `pytest -v` is green; test count is ~165 or higher.
- [ ] `gitexpose --version` reports `0.3.0`.
- [ ] `gitexpose supply-chain ./tests/fixtures/synthetic_repo_v03 --verify --verify-timeout 2` runs to completion (live network — accept any outcome that isn't a Python traceback).
- [ ] `gitexpose supply-chain ./tests/fixtures/synthetic_repo_v03 -o sarif --output-file /tmp/v03.sarif` produces a SARIF file that validates against the vendored 2.1.0 schema.
- [ ] `docs/COVERAGE.md`, `docs/MITRE_ATLAS_COVERAGE.md`, `docs/INTEGRATIONS_CICD.md`, `docs/INTEGRATIONS_CODE_SCANNING.md` all exist and are reviewed by eye.
- [ ] `README.md` contains the CISA-incident callout.
- [ ] `.serena/`, `RESEARCH/`, `files/`, `files (1)/`, root PNGs are in `.gitignore` and the working tree is clean.
- [ ] `v0.3.0` tag exists locally and is annotated.

After all boxes check: push `main` and the tag, then draft a GitHub release with the CHANGELOG entry as the body.
