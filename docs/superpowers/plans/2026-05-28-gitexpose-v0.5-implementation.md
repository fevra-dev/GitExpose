# GitExpose v0.5 "Supply-Chain Intelligence" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn GitExpose's static supply-chain signatures into real dependency SCA — parse Python/JS lock files, query OSV.dev for live vulnerability intelligence, and export a CycloneDX 1.6 AI-BOM with honestly-scoped VEX.

**Architecture:** A new cohesive `gitexpose/supply_chain/` package (parallel to `verification/` and `git_history/`) holds lock-file parsers, an async OSV.dev client, and a correlation layer that emits `vulnerable_dependency` finding-dicts. A new `gitexpose/reporters/cyclonedx_reporter.py` builds the BOM. The existing `supply-chain` CLI command is extended: after the existing `LocalFilesystemScanner.scan()`, it parses lock files, enriches via OSV (default on, `--offline` opt-out), merges findings, and renders console/json (existing) or CycloneDX (new). Findings are plain dicts throughout, matching the existing supply-chain path.

**Tech Stack:** Python ≥3.9, `click`, `httpx` (reused for OSV — async + `respx` for tests), `cyclonedx-python-lib` + `packageurl-python` (BOM), `tomli` (poetry.lock on 3.9/3.10; stdlib `tomllib` on 3.11+). Tests: `pytest`, `pytest-asyncio`, `respx`. Run tests with `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/`.

**Spec:** `docs/superpowers/specs/2026-05-28-gitexpose-v0.5-design.md`

---

## File Structure

**Create:**
- `gitexpose/supply_chain/__init__.py` — package exports
- `gitexpose/supply_chain/models.py` — `Dependency`, `Vulnerability` dataclasses
- `gitexpose/supply_chain/cvss.py` — CVSS v3.1 base-score computation + severity bucketing
- `gitexpose/supply_chain/lockfiles/__init__.py`
- `gitexpose/supply_chain/lockfiles/base.py` — name normalization + PURL + `parse_all` dispatcher
- `gitexpose/supply_chain/lockfiles/python.py` — requirements.txt / poetry.lock / Pipfile.lock
- `gitexpose/supply_chain/lockfiles/javascript.py` — package-lock.json / yarn.lock (v1 + Berry)
- `gitexpose/supply_chain/osv.py` — async OSV.dev client
- `gitexpose/supply_chain/correlate.py` — OSV+curated → `vulnerable_dependency` findings + exploitability ranking
- `gitexpose/reporters/cyclonedx_reporter.py` — CycloneDX 1.6 BOM builder
- Tests: `tests/test_lockfile_python.py`, `tests/test_lockfile_javascript.py`, `tests/test_lockfile_parse_all.py`, `tests/test_cvss.py`, `tests/test_osv_client.py`, `tests/test_correlate.py`, `tests/test_cyclonedx_reporter.py`, `tests/test_supply_chain_cli_v05.py`, `tests/test_smoke_v05.py`
- Fixtures: `tests/fixtures/lockfiles/` (one per format), `tests/fixtures/synthetic_repo_v05/`

**Modify:**
- `pyproject.toml` — add `cyclonedx-python-lib`, `packageurl-python` to core deps; `tomli` conditional; bump version to `0.5.0`
- `requirements.txt` — mirror new core deps
- `gitexpose/cli_advanced.py` — extend `supply-chain` command (new options, data flow, console rendering, cyclonedx output)
- `README.md`, `docs/COVERAGE.md`, `CHANGELOG.md` — docs (final task)

---

## Task 1: Dependencies + package skeleton + data models

**Files:**
- Modify: `pyproject.toml` (deps + version), `requirements.txt`
- Create: `gitexpose/supply_chain/__init__.py`, `gitexpose/supply_chain/models.py`
- Test: `tests/test_lockfile_python.py` (the import smoke at the bottom)

- [ ] **Step 1: Add dependencies to `pyproject.toml`**

In `[project]`, change `version = "0.4.0"` to `version = "0.5.0"`.

In `dependencies = [...]`, add three entries so the block reads:

```toml
dependencies = [
    "aiohttp>=3.9.0",
    "click>=8.1.0",
    "colorama>=0.4.6",
    "httpx>=0.27.0",
    "cyclonedx-python-lib>=8.0.0",
    "packageurl-python>=0.15.0",
    "tomli>=2.0.0; python_version < '3.11'",
]
```

- [ ] **Step 2: Mirror in `requirements.txt`**

Add under the core block:

```
cyclonedx-python-lib>=8.0.0
packageurl-python>=0.15.0
tomli>=2.0.0; python_version < "3.11"
```

- [ ] **Step 3: Install the new deps into the test interpreter**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pip install "cyclonedx-python-lib>=8.0.0" "packageurl-python>=0.15.0"`
Expected: successful install (tomli not needed on 3.12).

- [ ] **Step 4: Create `gitexpose/supply_chain/models.py`**

```python
"""Data models for the supply-chain SCA subsystem.

A Dependency is one resolved package from a lock file. A Vulnerability is one
OSV.dev advisory affecting it. Both are plain dataclasses; the CLI/reporter
layers convert them to the finding-dict shape used elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Dependency:
    name: str                       # normalized (PEP 503 for PyPI, lowercase for npm)
    version: str
    ecosystem: str                  # OSV ecosystem name: "PyPI" | "npm"
    purl: str                       # e.g. "pkg:pypi/requests@2.31.0"
    direct: bool                    # direct vs transitive (from lock-file structure)
    source_file: str                # e.g. "poetry.lock"
    integrity_hash: Optional[str] = None   # captured for BOM hashes + v0.6 poisoning checks
    resolved_url: Optional[str] = None     # captured for v0.6 poisoning checks


@dataclass
class Vulnerability:
    vuln_id: str                    # CVE-… / GHSA-… / MAL-…
    severity: str                   # CRITICAL|HIGH|MEDIUM|LOW
    summary: str
    advisory_url: str
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    known_exploited: bool = False
```

- [ ] **Step 5: Create `gitexpose/supply_chain/__init__.py`**

```python
"""GitExpose supply-chain SCA subsystem (lock-file parsing + OSV.dev + BOM)."""

from .models import Dependency, Vulnerability

__all__ = ["Dependency", "Vulnerability"]
```

- [ ] **Step 6: Write an import-smoke test in `tests/test_lockfile_python.py`**

```python
"""Tests for Python lock-file parsers."""

from gitexpose.supply_chain import Dependency, Vulnerability


def test_models_importable():
    d = Dependency(name="requests", version="2.31.0", ecosystem="PyPI",
                   purl="pkg:pypi/requests@2.31.0", direct=True, source_file="requirements.txt")
    assert d.name == "requests"
    v = Vulnerability(vuln_id="CVE-0000-0000", severity="HIGH", summary="x",
                      advisory_url="https://osv.dev/vulnerability/CVE-0000-0000")
    assert v.severity == "HIGH"
```

- [ ] **Step 7: Run the test**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_python.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml requirements.txt gitexpose/supply_chain/ tests/test_lockfile_python.py
git commit -m "feat(v0.5): supply_chain package skeleton + data models + deps"
```

---

## Task 2: Name normalization + PURL helpers

**Files:**
- Create: `gitexpose/supply_chain/lockfiles/__init__.py`, `gitexpose/supply_chain/lockfiles/base.py`
- Test: `tests/test_lockfile_parse_all.py`

- [ ] **Step 1: Write failing tests in `tests/test_lockfile_parse_all.py`**

```python
"""Tests for lock-file name normalization, PURL building, and the parse_all dispatcher."""

from gitexpose.supply_chain.lockfiles.base import normalize_name, make_purl


def test_normalize_pypi_pep503():
    assert normalize_name("Flask_SQLAlchemy", "PyPI") == "flask-sqlalchemy"
    assert normalize_name("ZopE.Interface", "PyPI") == "zope-interface"


def test_normalize_npm_lowercases():
    assert normalize_name("Lodash", "npm") == "lodash"
    assert normalize_name("@Angular/Core", "npm") == "@angular/core"


def test_make_purl_pypi():
    assert make_purl("requests", "2.31.0", "PyPI") == "pkg:pypi/requests@2.31.0"


def test_make_purl_npm_scoped():
    # scoped npm names encode the scope as a PURL namespace
    purl = make_purl("@angular/core", "17.0.0", "npm")
    assert purl == "pkg:npm/%40angular/core@17.0.0"
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_parse_all.py -v`
Expected: FAIL (module `gitexpose.supply_chain.lockfiles.base` not found).

- [ ] **Step 3: Create `gitexpose/supply_chain/lockfiles/__init__.py`**

```python
"""Lock-file parsers for the supply-chain SCA subsystem."""
```

- [ ] **Step 4: Create `gitexpose/supply_chain/lockfiles/base.py`**

```python
"""Name normalization, PURL building, and the parse_all dispatcher.

normalize_name() makes lookups consistent across lock files and OSV:
  - PyPI: PEP 503 (lowercase, collapse runs of -_. to a single -)
  - npm:  lowercase (names are case-insensitive; scopes preserved)
make_purl() builds a Package URL string for the BOM and OSV cross-reference.
parse_all() walks a directory, dispatches each recognized lock file to its
parser, and returns a de-duplicated Dependency list.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Dict, List

from packageurl import PackageURL

from ..models import Dependency

logger = logging.getLogger(__name__)

_PEP503_RUN = re.compile(r"[-_.]+")

# Directories never to descend into (mirrors LocalFilesystemScanner).
_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})


def normalize_name(name: str, ecosystem: str) -> str:
    name = name.strip()
    if ecosystem == "PyPI":
        return _PEP503_RUN.sub("-", name).lower()
    # npm
    return name.lower()


def make_purl(name: str, version: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return PackageURL(type="pypi", name=name, version=version).to_string()
    # npm — split a scoped name "@scope/pkg" into namespace + name
    namespace = None
    pkg = name
    if name.startswith("@") and "/" in name:
        namespace, pkg = name.split("/", 1)
    return PackageURL(type="npm", namespace=namespace, name=pkg, version=version).to_string()


# Filled in by Task 8 once the per-format parsers exist.
# Maps a lock-file basename -> parser callable(content: str, source: str) -> List[Dependency].
_PARSERS: Dict[str, Callable[[str, str], List[Dependency]]] = {}


def _register(basename: str, parser: Callable[[str, str], List[Dependency]]) -> None:
    _PARSERS[basename] = parser


def parse_all(root: Path) -> List[Dependency]:
    """Walk `root`, parse every recognized lock file, return deduped Dependencies.

    Dedup key is (name, version, ecosystem). When the same package appears in
    multiple files, the first occurrence wins but `direct=True` is sticky (a
    package that is direct anywhere is reported direct).
    """
    root = Path(root)
    by_key: Dict[tuple, Dependency] = {}
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        parser = _PARSERS.get(path.name)
        if parser is None:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("Could not read lock file %s: %s", path, exc)
            continue
        try:
            deps = parser(content, str(path.relative_to(root)))
        except Exception as exc:  # noqa: BLE001 — never let one bad file kill the scan
            logger.warning("Failed to parse %s: %s", path, exc)
            continue
        for dep in deps:
            key = (dep.name, dep.version, dep.ecosystem)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = dep
            elif dep.direct and not existing.direct:
                by_key[key] = dep
    return list(by_key.values())
```

- [ ] **Step 5: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_parse_all.py -v`
Expected: 4 PASS.

- [ ] **Step 6: Commit**

```bash
git add gitexpose/supply_chain/lockfiles/ tests/test_lockfile_parse_all.py
git commit -m "feat(v0.5): name normalization + PURL + parse_all dispatcher"
```

---

## Task 3: Python lock-file parsers (requirements.txt, poetry.lock, Pipfile.lock)

**Files:**
- Create: `gitexpose/supply_chain/lockfiles/python.py`
- Test: `tests/test_lockfile_python.py`; Fixtures: `tests/fixtures/lockfiles/poetry.lock`, `tests/fixtures/lockfiles/Pipfile.lock`

- [ ] **Step 1: Create fixture `tests/fixtures/lockfiles/poetry.lock`**

```toml
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
category = "main"
optional = false

[[package]]
name = "Flask-SQLAlchemy"
version = "3.0.5"
description = "Add SQLAlchemy support to your Flask application."
category = "main"
optional = false

[metadata]
content-hash = "abc123"
```

- [ ] **Step 2: Create fixture `tests/fixtures/lockfiles/Pipfile.lock`**

```json
{
  "_meta": {"hash": {"sha256": "deadbeef"}},
  "default": {
    "requests": {"version": "==2.31.0", "hashes": ["sha256:aaa"]},
    "urllib3": {"version": "==2.0.7"}
  },
  "develop": {
    "pytest": {"version": "==7.4.0"}
  }
}
```

- [ ] **Step 3: Write failing tests in `tests/test_lockfile_python.py`** (append below the existing test)

```python
from pathlib import Path

from gitexpose.supply_chain.lockfiles.python import (
    parse_requirements, parse_poetry_lock, parse_pipfile_lock,
)

FIX = Path(__file__).parent / "fixtures" / "lockfiles"


def test_parse_requirements_pins_only():
    content = "requests==2.31.0\nflask>=2.0  # unpinned, ignored for SCA\nurllib3==2.0.7\n"
    deps = parse_requirements(content, "requirements.txt")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].ecosystem == "PyPI"
    assert by_name["requests"].direct is True
    assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"
    # only hard pins (==) produce a versioned Dependency for OSV lookup
    assert "flask" not in by_name


def test_parse_poetry_lock_normalizes_names():
    deps = parse_poetry_lock((FIX / "poetry.lock").read_text(), "poetry.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["flask-sqlalchemy"].version == "3.0.5"   # PEP 503 normalized
    assert all(d.ecosystem == "PyPI" for d in deps)


def test_parse_pipfile_lock_default_and_develop():
    deps = parse_pipfile_lock((FIX / "Pipfile.lock").read_text(), "Pipfile.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["pytest"].version == "7.4.0"     # develop deps included
    assert by_name["requests"].integrity_hash == "sha256:aaa"
```

- [ ] **Step 4: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_python.py -v`
Expected: FAIL (module `python` not found).

- [ ] **Step 5: Create `gitexpose/supply_chain/lockfiles/python.py`**

```python
"""Python lock-file parsers: requirements.txt, poetry.lock, Pipfile.lock.

requirements.txt: only hard pins (==) yield a versioned Dependency (a range is
not a resolved version, so it can't be queried against OSV by exact version).
poetry.lock / Pipfile.lock: fully resolved, so every entry is captured.
"""

from __future__ import annotations

import json
import re
import sys
from typing import List

from ..models import Dependency
from .base import make_purl, normalize_name, _register

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.9/3.10
    import tomli as tomllib

_ECO = "PyPI"

# requirements line: name[extras]==version  (we only keep == pins)
_REQ_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<version>[^\s;#]+)"
)


def _dep(name: str, version: str, source: str, *, direct: bool,
         integrity_hash: str | None = None) -> Dependency:
    norm = normalize_name(name, _ECO)
    return Dependency(
        name=norm, version=version, ecosystem=_ECO,
        purl=make_purl(norm, version, _ECO), direct=direct,
        source_file=source, integrity_hash=integrity_hash,
    )


def parse_requirements(content: str, source: str = "requirements.txt") -> List[Dependency]:
    out: List[Dependency] = []
    for line in content.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        m = _REQ_PIN.match(stripped)
        if not m:
            continue
        out.append(_dep(m.group("name"), m.group("version"), source, direct=True))
    return out


def parse_poetry_lock(content: str, source: str = "poetry.lock") -> List[Dependency]:
    data = tomllib.loads(content)
    out: List[Dependency] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        # poetry.lock does not mark direct vs transitive; treat all as non-direct
        # except we cannot know — default False (conservative for exploitability).
        out.append(_dep(name, version, source, direct=False))
    return out


def parse_pipfile_lock(content: str, source: str = "Pipfile.lock") -> List[Dependency]:
    data = json.loads(content)
    out: List[Dependency] = []
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            version_spec = (meta or {}).get("version", "")
            version = version_spec.lstrip("=") if version_spec else ""
            if not version:
                continue
            hashes = (meta or {}).get("hashes") or []
            integrity = hashes[0] if hashes else None
            out.append(_dep(name, version, source, direct=direct, integrity_hash=integrity))
    return out


_register("requirements.txt", parse_requirements)
_register("requirements-dev.txt", parse_requirements)
_register("poetry.lock", parse_poetry_lock)
_register("Pipfile.lock", parse_pipfile_lock)
```

- [ ] **Step 6: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_python.py -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add gitexpose/supply_chain/lockfiles/python.py tests/test_lockfile_python.py tests/fixtures/lockfiles/
git commit -m "feat(v0.5): Python lock-file parsers (requirements/poetry/pipfile)"
```

---

## Task 4: JavaScript lock-file parsers (package-lock.json, yarn.lock)

**Files:**
- Create: `gitexpose/supply_chain/lockfiles/javascript.py`
- Test: `tests/test_lockfile_javascript.py`; Fixtures: `tests/fixtures/lockfiles/package-lock.json`, `tests/fixtures/lockfiles/yarn.lock`

- [ ] **Step 1: Create fixture `tests/fixtures/lockfiles/package-lock.json`** (v3 `packages` shape)

```json
{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "dependencies": {"lodash": "^4.17.21"}},
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-AAAA"
    },
    "node_modules/@angular/core": {
      "version": "17.0.0",
      "resolved": "https://registry.npmjs.org/@angular/core/-/core-17.0.0.tgz",
      "integrity": "sha512-BBBB"
    }
  }
}
```

- [ ] **Step 2: Create fixture `tests/fixtures/lockfiles/yarn.lock`** (v1 classic format)

```
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
  integrity sha512-CCCC

"@angular/core@^17.0.0":
  version "17.0.0"
  resolved "https://registry.yarnpkg.com/@angular/core/-/core-17.0.0.tgz#def"
```

- [ ] **Step 3: Write failing tests in `tests/test_lockfile_javascript.py`**

```python
"""Tests for JavaScript lock-file parsers."""

from pathlib import Path

from gitexpose.supply_chain.lockfiles.javascript import (
    parse_package_lock, parse_yarn_lock,
)

FIX = Path(__file__).parent / "fixtures" / "lockfiles"


def test_parse_package_lock_v3():
    deps = parse_package_lock((FIX / "package-lock.json").read_text(), "package-lock.json")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].ecosystem == "npm"
    assert by_name["lodash"].integrity_hash == "sha512-AAAA"
    assert by_name["lodash"].resolved_url.endswith("lodash-4.17.21.tgz")
    assert by_name["@angular/core"].version == "17.0.0"
    assert by_name["@angular/core"].purl == "pkg:npm/%40angular/core@17.0.0"


def test_parse_yarn_lock_v1():
    deps = parse_yarn_lock((FIX / "yarn.lock").read_text(), "yarn.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].integrity_hash == "sha512-CCCC"
    assert by_name["@angular/core"].version == "17.0.0"
```

- [ ] **Step 4: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_javascript.py -v`
Expected: FAIL (module not found).

- [ ] **Step 5: Create `gitexpose/supply_chain/lockfiles/javascript.py`**

```python
"""JavaScript lock-file parsers: package-lock.json (v2/v3) and yarn.lock (v1 + Berry).

package-lock.json v2/v3 puts resolved packages under the `packages` object keyed
by install path ("node_modules/<name>" or nested). yarn.lock v1 is a custom
text format; Berry (v2+) is YAML-ish but regular enough to parse with the same
line scanner for the fields we need (version / resolved / integrity).
"""

from __future__ import annotations

import json
import re
from typing import List

from ..models import Dependency
from .base import make_purl, normalize_name, _register

_ECO = "npm"

_NM_PREFIX = "node_modules/"


def _dep(name: str, version: str, source: str, *, direct: bool,
         integrity: str | None, resolved: str | None) -> Dependency:
    norm = normalize_name(name, _ECO)
    return Dependency(
        name=norm, version=version, ecosystem=_ECO,
        purl=make_purl(norm, version, _ECO), direct=direct,
        source_file=source, integrity_hash=integrity, resolved_url=resolved,
    )


def parse_package_lock(content: str, source: str = "package-lock.json") -> List[Dependency]:
    data = json.loads(content)
    out: List[Dependency] = []

    # Direct deps are declared on the root package ("" key) in v2/v3.
    root = (data.get("packages") or {}).get("", {})
    direct_names = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        direct_names.update((root.get(field) or {}).keys())

    packages = data.get("packages")
    if packages:  # v2/v3
        for path, meta in packages.items():
            if not path or "version" not in meta:
                continue
            # The package name is the path segment after the LAST node_modules/.
            name = path.rsplit(_NM_PREFIX, 1)[-1]
            out.append(_dep(
                name, meta["version"], source,
                direct=name in direct_names,
                integrity=meta.get("integrity"),
                resolved=meta.get("resolved"),
            ))
        return out

    # v1 fallback: flat `dependencies` map keyed by name.
    for name, meta in (data.get("dependencies") or {}).items():
        if "version" not in meta:
            continue
        out.append(_dep(
            name, meta["version"], source, direct=name in direct_names,
            integrity=meta.get("integrity"), resolved=meta.get("resolved"),
        ))
    return out


# A yarn.lock entry header is one or more comma-separated "spec" strings ending
# in ":", e.g.  lodash@^4.17.21:   or   "@angular/core@^17.0.0", "@angular/core@17":
_YARN_VERSION = re.compile(r'^\s+version[ :]+"?([^"\s]+)"?', re.MULTILINE)


def parse_yarn_lock(content: str, source: str = "yarn.lock") -> List[Dependency]:
    out: List[Dependency] = []
    # Split into blocks separated by blank lines; each block is one package entry.
    block: List[str] = []
    blocks: List[List[str]] = []
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            if block:
                blocks.append(block)
                block = []
            continue
        block.append(line)
    if block:
        blocks.append(block)

    for blk in blocks:
        header = blk[0]
        if header.startswith(" ") or not header.rstrip().endswith(":"):
            continue
        name = _yarn_name_from_header(header)
        if not name:
            continue
        body = "\n".join(blk[1:])
        vmatch = _YARN_VERSION.search("\n" + body)
        if not vmatch:
            continue
        version = vmatch.group(1)
        integrity = _yarn_field(body, "integrity")
        resolved = _yarn_field(body, "resolved")
        out.append(_dep(name, version, source, direct=True,
                        integrity=integrity, resolved=resolved))
    return out


def _yarn_name_from_header(header: str) -> str:
    """Extract the package name from a yarn entry header line.

    The header is a comma-separated list of "<name>@<range>" specs, optionally
    quoted, ending with ":". We take the first spec and strip the @range. Scoped
    names start with "@", so we split on the LAST "@".
    """
    first_spec = header.rstrip(":").split(",")[0].strip().strip('"')
    at = first_spec.rfind("@")
    if at <= 0:  # no range, or "@" only at index 0 (malformed)
        return first_spec
    return first_spec[:at]


def _yarn_field(body: str, field: str) -> str | None:
    m = re.search(rf'^\s+{field}[ :]+"?([^"\s]+)"?', body, re.MULTILINE)
    return m.group(1) if m else None


_register("package-lock.json", parse_package_lock)
_register("yarn.lock", parse_yarn_lock)
```

- [ ] **Step 6: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_javascript.py -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add gitexpose/supply_chain/lockfiles/javascript.py tests/test_lockfile_javascript.py tests/fixtures/lockfiles/package-lock.json tests/fixtures/lockfiles/yarn.lock
git commit -m "feat(v0.5): JavaScript lock-file parsers (package-lock + yarn)"
```

---

## Task 5: Wire parsers into parse_all + integration test

**Files:**
- Modify: `gitexpose/supply_chain/lockfiles/base.py` (ensure parsers are imported so `_register` runs)
- Test: `tests/test_lockfile_parse_all.py`

- [ ] **Step 1: Add parser imports to `gitexpose/supply_chain/lockfiles/__init__.py`**

Replace the file contents with:

```python
"""Lock-file parsers for the supply-chain SCA subsystem.

Importing the package registers every parser with the base dispatcher.
"""

from . import base  # noqa: F401
from . import python  # noqa: F401  (registers requirements/poetry/pipfile)
from . import javascript  # noqa: F401  (registers package-lock/yarn)

from .base import parse_all, normalize_name, make_purl

__all__ = ["parse_all", "normalize_name", "make_purl"]
```

- [ ] **Step 2: Write failing integration test in `tests/test_lockfile_parse_all.py`** (append)

```python
from pathlib import Path

from gitexpose.supply_chain.lockfiles import parse_all


def test_parse_all_walks_mixed_repo(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{},'
        '"node_modules/lodash":{"version":"4.17.21"}}}'
    )
    # ignored: inside a skip-dir
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "requirements.txt").write_text("evil==6.6.6\n")

    deps = parse_all(tmp_path)
    names = {d.name for d in deps}
    assert "requests" in names
    assert "lodash" in names
    assert "evil" not in names   # node_modules is skipped
```

- [ ] **Step 3: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_lockfile_parse_all.py -v`
Expected: all PASS (the import side-effect registers parsers).

- [ ] **Step 4: Commit**

```bash
git add gitexpose/supply_chain/lockfiles/__init__.py tests/test_lockfile_parse_all.py
git commit -m "feat(v0.5): register parsers + parse_all integration"
```

---

## Task 6: CVSS v3.1 base-score + severity bucketing

**Files:**
- Create: `gitexpose/supply_chain/cvss.py`
- Test: `tests/test_cvss.py`

- [ ] **Step 1: Write failing tests in `tests/test_cvss.py`**

```python
"""Tests for CVSS v3.1 base-score computation and severity bucketing."""

import pytest

from gitexpose.supply_chain.cvss import base_score_from_vector, bucket, severity_from_osv


@pytest.mark.parametrize("vector, expected", [
    # Official CVSS 3.1 examples
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),    # critical
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),    # high
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),    # low
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),    # scope changed
])
def test_base_score_known_vectors(vector, expected):
    assert base_score_from_vector(vector) == pytest.approx(expected, abs=0.05)


def test_bucket_thresholds():
    assert bucket(9.8) == "CRITICAL"
    assert bucket(7.5) == "HIGH"
    assert bucket(5.0) == "MEDIUM"
    assert bucket(1.8) == "LOW"


def test_severity_from_osv_prefers_qualitative():
    osv = {"database_specific": {"severity": "HIGH"}}
    sev, score = severity_from_osv(osv)
    assert sev == "HIGH"
    assert score is None


def test_severity_from_osv_uses_cvss_vector():
    osv = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    sev, score = severity_from_osv(osv)
    assert sev == "CRITICAL"
    assert score == pytest.approx(9.8, abs=0.05)


def test_severity_from_osv_defaults_medium():
    sev, score = severity_from_osv({})
    assert sev == "MEDIUM"
    assert score is None
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cvss.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Create `gitexpose/supply_chain/cvss.py`**

```python
"""CVSS v3.1 base-score computation and severity bucketing.

OSV's `severity` field carries a CVSS *vector string* (not a number), while
GHSA-sourced advisories carry a qualitative `database_specific.severity`. We
prefer the qualitative string when present and otherwise compute the v3.1 base
score from the vector with the official formula (FIRST CVSS v3.1 spec §7.1).
No external CVSS library — the formula is small and deterministic.
"""

from __future__ import annotations

import math
from typing import Optional, Tuple

# Metric weights (CVSS v3.1 spec, Table on §7.4)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(value: float) -> float:
    """Official CVSS v3.1 Roundup (spec Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score_from_vector(vector: str) -> Optional[float]:
    try:
        parts = dict(
            kv.split(":", 1) for kv in vector.split("/") if ":" in kv and not kv.startswith("CVSS")
        )
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def bucket(score: Optional[float]) -> str:
    if score is None:
        return "MEDIUM"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


_QUALITATIVE = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH",
    "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW",
}


def severity_from_osv(osv_vuln: dict) -> Tuple[str, Optional[float]]:
    """Return (severity_bucket, cvss_score|None) for an OSV vulnerability object."""
    # 1. Qualitative severity (GHSA) wins — no score to report.
    qual = ((osv_vuln.get("database_specific") or {}).get("severity") or "").upper()
    if qual in _QUALITATIVE:
        return _QUALITATIVE[qual], None
    # 2. CVSS vector → compute base score.
    for sev in osv_vuln.get("severity") or []:
        if str(sev.get("type", "")).startswith("CVSS") and sev.get("score"):
            score = base_score_from_vector(sev["score"])
            if score is not None:
                return bucket(score), score
    # 3. Default.
    return "MEDIUM", None
```

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cvss.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/supply_chain/cvss.py tests/test_cvss.py
git commit -m "feat(v0.5): CVSS v3.1 base-score + severity bucketing"
```

---

## Task 7: OSV.dev async client

**Files:**
- Create: `gitexpose/supply_chain/osv.py`
- Test: `tests/test_osv_client.py`

- [ ] **Step 1: Write failing tests in `tests/test_osv_client.py`**

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_osv_client.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Create `gitexpose/supply_chain/osv.py`**

```python
"""Async OSV.dev client.

Flow: POST /v1/querybatch (≤1000 packages/request) returns vuln IDs per query;
then hydrate each unique ID via GET /v1/vulns/{id} for severity/fix/summary.
Network failures degrade to an empty map so the caller can fall back to the
curated KNOWN_BAD_VERSIONS list. Sends only package names + versions — no secrets.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

import httpx

from .models import Dependency, Vulnerability
from .cvss import severity_from_osv

logger = logging.getLogger(__name__)

_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_BATCH_SIZE = 1000
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_CONCURRENCY = 8
_USER_AGENT = "GitExpose-SCA/0.5"


def _fixed_version(osv_vuln: dict) -> str | None:
    for affected in osv_vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _to_vulnerability(osv_vuln: dict) -> Vulnerability:
    vuln_id = osv_vuln.get("id", "UNKNOWN")
    severity, score = severity_from_osv(osv_vuln)
    return Vulnerability(
        vuln_id=vuln_id,
        severity=severity,
        cvss_score=score,
        summary=osv_vuln.get("summary") or osv_vuln.get("details", "")[:200] or vuln_id,
        advisory_url=f"https://osv.dev/vulnerability/{vuln_id}",
        fixed_version=_fixed_version(osv_vuln),
        aliases=list(osv_vuln.get("aliases") or []),
        known_exploited=bool((osv_vuln.get("database_specific") or {}).get("known_exploited", False)),
    )


async def query_osv(
    deps: List[Dependency],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    concurrency: int = _DEFAULT_CONCURRENCY,
    max_deps: int = 5000,
) -> Dict[str, List[Vulnerability]]:
    """Return {purl: [Vulnerability, ...]} for the given dependencies.

    Returns {} on any network failure (caller degrades to the curated list).
    """
    if not deps:
        return {}
    deps = deps[:max_deps]
    result: Dict[str, List[Vulnerability]] = {d.purl: [] for d in deps}

    try:
        async with httpx.AsyncClient(
            timeout=timeout, headers={"User-Agent": _USER_AGENT}
        ) as client:
            # Phase 1: batch query → vuln IDs per dependency.
            purl_to_ids: Dict[str, List[str]] = {}
            for start in range(0, len(deps), _BATCH_SIZE):
                chunk = deps[start:start + _BATCH_SIZE]
                queries = [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                    for d in chunk
                ]
                resp = await client.post(_QUERYBATCH_URL, json={"queries": queries})
                resp.raise_for_status()
                results = resp.json().get("results", [])
                for dep, entry in zip(chunk, results):
                    ids = [v["id"] for v in (entry or {}).get("vulns", []) if v.get("id")]
                    if ids:
                        purl_to_ids[dep.purl] = ids

            # Phase 2: hydrate each unique vuln ID once.
            unique_ids = {vid for ids in purl_to_ids.values() for vid in ids}
            sem = asyncio.Semaphore(concurrency)
            hydrated: Dict[str, Vulnerability] = {}

            async def _hydrate(vid: str) -> None:
                async with sem:
                    r = await client.get(_VULN_URL.format(id=vid))
                    if r.status_code == 200:
                        hydrated[vid] = _to_vulnerability(r.json())

            await asyncio.gather(*(_hydrate(vid) for vid in unique_ids))

            for purl, ids in purl_to_ids.items():
                result[purl] = [hydrated[i] for i in ids if i in hydrated]
    except httpx.HTTPError as exc:
        logger.warning("OSV lookup failed (%s); falling back to curated list.", type(exc).__name__)
        return {}

    return result
```

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_osv_client.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/supply_chain/osv.py tests/test_osv_client.py
git commit -m "feat(v0.5): async OSV.dev client (querybatch + hydrate + degrade)"
```

---

## Task 8: Correlation → vulnerable_dependency findings + exploitability ranking

**Files:**
- Create: `gitexpose/supply_chain/correlate.py`
- Test: `tests/test_correlate.py`

- [ ] **Step 1: Write failing tests in `tests/test_correlate.py`**

```python
"""Tests for correlating OSV results into vulnerable_dependency findings."""

from gitexpose.supply_chain import Dependency, Vulnerability
from gitexpose.supply_chain.correlate import build_vuln_findings, exploitability_sort_key


def _dep(name="lodash", version="4.17.20", direct=True):
    return Dependency(name=name, version=version, ecosystem="npm",
                      purl=f"pkg:npm/{name}@{version}", direct=direct, source_file="package-lock.json")


def _vuln(severity="HIGH", fixed="4.17.21", known_exploited=False):
    return Vulnerability(vuln_id="GHSA-xxxx", severity=severity, summary="proto pollution",
                         advisory_url="https://osv.dev/vulnerability/GHSA-xxxx",
                         cvss_score=7.5, fixed_version=fixed, aliases=["CVE-2020-8203"],
                         known_exploited=known_exploited)


def test_build_vuln_findings_shape():
    dep = _dep()
    findings = build_vuln_findings({dep.purl: [_vuln()]}, [dep],
                                   unpinned_packages=set(), cred_sources=set())
    f = findings[0]
    assert f["type"] == "vulnerable_dependency"
    assert f["package"] == "lodash"
    assert f["vuln_id"] == "GHSA-xxxx"
    assert f["severity"] == "HIGH"
    assert f["fixed_version"] == "4.17.21"
    assert f["fix_available"] is True
    assert f["direct"] is True
    assert f["attack_class"] == "OWASP A06:2021 Vulnerable & Outdated Components"
    assert f["verification_status"] == "skipped"


def test_cred_co_presence_marks_exploitable_signal():
    dep = _dep()
    findings = build_vuln_findings({dep.purl: [_vuln()]}, [dep],
                                   unpinned_packages=set(),
                                   cred_sources={"package-lock.json"})
    assert findings[0]["cred_co_present"] is True


def test_exploitability_sort_prioritizes_direct_unpinned_over_higher_cvss():
    # transitive CRITICAL (cvss 9.8) vs direct+unpinned+fix HIGH (cvss 7.5)
    high_direct = {"severity": "HIGH", "cvss_score": 7.5, "direct": True,
                   "pinned": False, "fix_available": True, "cred_co_present": False}
    crit_transitive = {"severity": "CRITICAL", "cvss_score": 9.8, "direct": False,
                       "pinned": True, "fix_available": False, "cred_co_present": False}
    ordered = sorted([crit_transitive, high_direct], key=exploitability_sort_key, reverse=True)
    assert ordered[0] is high_direct   # exploitability context beats raw CVSS
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_correlate.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Create `gitexpose/supply_chain/correlate.py`**

```python
"""Turn OSV results into vulnerable_dependency finding-dicts + exploitability ranking.

The CVSS-scoring discipline (spec §6): rank by exploitability *context*
(direct / fix-available / unpinned / credential co-presence), with CVSS as a
secondary key — not the primary one. A finding nobody has proven exploitable is
a hypothesis, not a vulnerability.
"""

from __future__ import annotations

from typing import Dict, List, Set

from .models import Dependency, Vulnerability

_ATTACK_CLASS = "OWASP A06:2021 Vulnerable & Outdated Components"

# AI middleware packages keep an ATLAS tag (mirrors known_bad_versions).
_AI_MIDDLEWARE = frozenset({
    "litellm", "langchain", "langchain-core", "langchain-community",
    "llama-index", "llama-index-core", "autogen", "crewai", "openai", "anthropic",
})

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def build_vuln_findings(
    osv_map: Dict[str, List[Vulnerability]],
    deps: List[Dependency],
    *,
    unpinned_packages: Set[str],
    cred_sources: Set[str],
) -> List[Dict]:
    """Build vulnerable_dependency finding-dicts from the OSV map.

    `unpinned_packages` = normalized names flagged unpinned by dependency_pinning.
    `cred_sources` = source files where a credential finding was detected
    (used for the credential-co-presence exploitability signal).
    """
    by_purl = {d.purl: d for d in deps}
    findings: List[Dict] = []
    for purl, vulns in osv_map.items():
        dep = by_purl.get(purl)
        if dep is None:
            continue
        pinned = dep.name not in unpinned_packages
        cred_co_present = dep.source_file in cred_sources
        for v in vulns:
            findings.append({
                "type": "vulnerable_dependency",
                "package": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem,
                "purl": dep.purl,
                "vuln_id": v.vuln_id,
                "aliases": v.aliases,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "fixed_version": v.fixed_version,
                "fix_available": v.fixed_version is not None,
                "summary": v.summary,
                "advisory_url": v.advisory_url,
                "source": dep.source_file,
                "direct": dep.direct,
                "pinned": pinned,
                "cred_co_present": cred_co_present,
                "known_exploited": v.known_exploited,
                "attack_class": _ATTACK_CLASS,
                "atlas_technique": "AML.T0019" if dep.name in _AI_MIDDLEWARE else None,
                "verification_status": "skipped",
                "verification_detail": None,
            })
    return findings


def exploitability_sort_key(finding: Dict) -> tuple:
    """Primary sort by exploitability context; CVSS is only the tiebreaker.

    Higher tuple = more exploitable = sorted first (use reverse=True).
    """
    return (
        1 if finding.get("cred_co_present") else 0,
        1 if finding.get("known_exploited") else 0,
        1 if finding.get("direct") else 0,
        1 if not finding.get("pinned") else 0,
        1 if finding.get("fix_available") else 0,
        _SEV_ORDER.get((finding.get("severity") or "").upper(), 0),
        finding.get("cvss_score") or 0.0,
    )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_correlate.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/supply_chain/correlate.py tests/test_correlate.py
git commit -m "feat(v0.5): correlate OSV → vulnerable_dependency findings + exploitability ranking"
```

---

## Task 9: CycloneDX 1.6 AI-BOM reporter

**Files:**
- Create: `gitexpose/reporters/cyclonedx_reporter.py`
- Test: `tests/test_cyclonedx_reporter.py`

- [ ] **Step 1: Write failing tests in `tests/test_cyclonedx_reporter.py`**

```python
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
    }]
    doc = json.loads(build_bom(deps, findings))
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "exploitable"
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cyclonedx_reporter.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Create `gitexpose/reporters/cyclonedx_reporter.py`**

> NOTE on the library API: **Verified against `cyclonedx-python-lib` 11.7.0** (the
> code below was executed end-to-end and serializes valid CycloneDX 1.6 JSON). Key
> facts confirmed: `bom.metadata.tools` is a `ToolRepository` with a `.components`
> SortedSet; `bom.components` / `bom.vulnerabilities` are SortedSets with `.add()`;
> serialization is `make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6).output_as_string(indent=2)`.
> A `Component.bom_ref.value` is `None` until serialization auto-assigns a UUID — so
> we set an **explicit** `bom_ref=dep.purl` on each component and reuse that same
> string for the VEX `BomTarget(ref=...)`, guaranteeing the affects→component link.

```python
"""CycloneDX 1.6 AI-BOM builder for the supply-chain command.

Takes the parsed Dependency inventory + vulnerable_dependency findings and emits
a CycloneDX 1.6 JSON document with components, dependency-vulnerability VEX, and
NTIA minimum elements. VEX analysis state is honestly scoped (spec §6): default
`in_triage`; `exploitable` only when a co-present credential was verified live or
OSV flags the vuln known-exploited. We never assert `not_affected`.
"""

from __future__ import annotations

from typing import Dict, List

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import (
    BomTarget, Vulnerability as CdxVulnerability, VulnerabilityAdvisory,
    VulnerabilityAnalysis, VulnerabilitySource, ImpactAnalysisState,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from ..supply_chain.models import Dependency

_TOOL_NAME = "GitExpose"
_TOOL_VERSION = "0.5.0"


def _vex_state(finding: Dict) -> ImpactAnalysisState:
    """Honest VEX state: exploitable only when proven, else in_triage."""
    verified_cred = finding.get("cred_co_present") and finding.get("verification_status") == "verified"
    if verified_cred or finding.get("known_exploited"):
        return ImpactAnalysisState.EXPLOITABLE
    return ImpactAnalysisState.IN_TRIAGE


def build_bom(deps: List[Dependency], findings: List[Dict]) -> str:
    bom = Bom()
    bom.metadata.tools.components.add(
        Component(name=_TOOL_NAME, version=_TOOL_VERSION, type=ComponentType.APPLICATION)
    )

    # Components — every parsed dependency (NTIA: name, version, PURL, hash).
    # Set an EXPLICIT bom_ref (= purl) so the VEX affects-ref is stable and
    # matches the component (Component.bom_ref.value is None until serialization).
    known_purls = set()
    for dep in deps:
        comp = Component(
            name=dep.name,
            version=dep.version,
            type=ComponentType.LIBRARY,
            bom_ref=dep.purl,
            purl=PackageURL.from_string(dep.purl),
            properties=[
                Property(name="gitexpose:direct", value=str(dep.direct).lower()),
                Property(name="gitexpose:source", value=dep.source_file),
            ],
        )
        bom.components.add(comp)
        known_purls.add(dep.purl)

    # Vulnerabilities (VEX) from vulnerable_dependency findings.
    for f in findings:
        if f.get("type") != "vulnerable_dependency":
            continue
        purl = f.get("purl")
        advisories = []
        if f.get("advisory_url"):
            advisories.append(VulnerabilityAdvisory(url=f["advisory_url"]))
        affects = [BomTarget(ref=purl)] if purl in known_purls else []
        vuln = CdxVulnerability(
            id=f["vuln_id"],
            source=VulnerabilitySource(name="OSV", url=f.get("advisory_url")),
            description=f.get("summary"),
            advisories=advisories,
            analysis=VulnerabilityAnalysis(state=_vex_state(f)),
            affects=affects,
        )
        bom.vulnerabilities.add(vuln)

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return outputter.output_as_string(indent=2)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_cyclonedx_reporter.py -v`
Expected: all PASS. **If an import name fails** (library version skew), adjust the import per the NOTE above, re-run until green.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/reporters/cyclonedx_reporter.py tests/test_cyclonedx_reporter.py
git commit -m "feat(v0.5): CycloneDX 1.6 AI-BOM reporter with honest VEX"
```

---

## Task 10: Wire SCA into the supply-chain CLI command

**Files:**
- Modify: `gitexpose/cli_advanced.py` (the `supply_chain` command, ~lines 842-932)
- Test: `tests/test_supply_chain_cli_v05.py`

- [ ] **Step 1: Write failing CLI tests in `tests/test_supply_chain_cli_v05.py`**

```python
"""CLI tests for v0.5 supply-chain SCA (lock-file + OSV + cyclonedx)."""

import json
from pathlib import Path

import httpx
import respx
from click.testing import CliRunner

from gitexpose.cli_advanced import cli

QUERYBATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/GHSA-xxxx"


def _write_repo(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.20"}},'
        '"node_modules/lodash":{"version":"4.17.20",'
        '"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",'
        '"integrity":"sha512-AAAA"}}}'
    )
    return tmp_path


def _mock_osv():
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]}))
    respx.get(VULN).mock(return_value=httpx.Response(200, json={
        "id": "GHSA-xxxx", "summary": "proto pollution",
        "aliases": ["CVE-2020-8203"], "database_specific": {"severity": "HIGH"},
        "affected": [{"ranges": [{"type": "ECOSYSTEM",
                     "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    }))


@respx.mock
def test_offline_skips_osv(tmp_path):
    _write_repo(tmp_path)
    route = respx.post(QUERYBATCH)
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "--offline", "-o", "json"])
    assert not route.called   # --offline made no network call
    # exit 0/1 both fine depending on other findings; just assert it ran
    assert result.exit_code in (0, 1)


@respx.mock
def test_osv_default_on_emits_vulnerable_dependency(tmp_path):
    _write_repo(tmp_path)
    _mock_osv()
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "-o", "json"])
    findings = json.loads(result.output)
    vuln = [f for f in findings if f["type"] == "vulnerable_dependency"]
    assert vuln and vuln[0]["vuln_id"] == "GHSA-xxxx"
    assert vuln[0]["severity"] == "HIGH"


@respx.mock
def test_cyclonedx_output(tmp_path):
    _write_repo(tmp_path)
    _mock_osv()
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "-o", "cyclonedx"])
    doc = json.loads(result.output)
    assert doc["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "lodash" for c in doc["components"])
    assert doc["vulnerabilities"][0]["id"] == "GHSA-xxxx"
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_supply_chain_cli_v05.py -v`
Expected: FAIL (`cyclonedx` not a valid `--output` choice; no vulnerable_dependency findings).

- [ ] **Step 3: Update the `supply_chain` command signature + options in `gitexpose/cli_advanced.py`**

Replace the decorator block and signature (currently lines ~842-849) with:

```python
@cli.command("supply-chain")
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option("-o", "--output", type=click.Choice(["console", "json", "cyclonedx", "aibom"]),
              default="console")
@click.option("--out-file", type=click.Path(), help="Write output to file instead of stdout")
@click.option("--offline", is_flag=True, default=False,
              help="Skip OSV.dev network lookups; use the curated known-bad list only.")
@click.option("--osv-timeout", type=float, default=10.0, metavar="SECS",
              help="Per-request OSV.dev timeout (default 10s).")
@click.option("--osv-max", type=int, default=5000, metavar="N",
              help="Cap dependencies queried against OSV.dev (default 5000).")
@add_verify_args
def supply_chain(path: str, output: str, out_file: str, offline: bool,
                 osv_timeout: float, osv_max: int, verify: bool,
                 verify_concurrency: int, verify_timeout: float,
                 verify_only_severity: str, no_verify_banner: bool):
    """Scan a local directory for supply-chain risks (TeamPCP-class) + live SCA."""
    from .advanced.local_fs_scanner import LocalFilesystemScanner

    scanner = LocalFilesystemScanner()
    findings = scanner.scan(Path(path))
```

- [ ] **Step 4: Insert the SCA pipeline** — immediately after `findings = scanner.scan(Path(path))` and BEFORE the `for f in findings: f.setdefault("verification_status", ...)` block, insert:

```python
    # --- v0.5: lock-file SCA + OSV.dev live vulnerability intelligence ---
    import asyncio as _asyncio
    from .supply_chain.lockfiles import parse_all
    from .supply_chain.osv import query_osv
    from .supply_chain.correlate import build_vuln_findings, exploitability_sort_key

    deps = parse_all(Path(path))

    # Credential co-presence: which source files already produced a credential finding?
    cred_sources = {
        f.get("source") for f in findings
        if f.get("value_full") or f.get("secret") or f.get("type", "").endswith("_key")
    }
    # Unpinned packages flagged by the existing dependency_pinning scanner.
    unpinned_packages = {
        (f.get("package") or "").lower().replace("_", "-")
        for f in findings if f.get("type") == "unpinned_ai_middleware"
    }

    osv_map = {}
    if not offline and deps:
        if not no_verify_banner:
            click.echo(
                f"ℹ  Querying OSV.dev for {min(len(deps), osv_max)} dependencies "
                "(package names + versions only; use --offline to disable).",
                err=True,
            )
        osv_map = _asyncio.run(query_osv(deps, timeout=osv_timeout, max_deps=osv_max))

    vuln_findings = build_vuln_findings(
        osv_map, deps, unpinned_packages=unpinned_packages, cred_sources=cred_sources
    )
    vuln_findings.sort(key=exploitability_sort_key, reverse=True)
    findings = findings + vuln_findings
    _v05_deps = deps  # retained for cyclonedx output below
```

- [ ] **Step 5: Add the CycloneDX output branch** — in the rendering section, change the output dispatch. Replace:

```python
    if output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    else:
```

with:

```python
    if output in ("cyclonedx", "aibom"):
        from .reporters.cyclonedx_reporter import build_bom
        text = build_bom(_v05_deps, findings)
    elif output == "json":
        import json as _json
        text = _json.dumps(findings, indent=2, default=str)
    else:
```

- [ ] **Step 6: Run the CLI tests to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_supply_chain_cli_v05.py -v`
Expected: all PASS.

- [ ] **Step 7: Run the existing supply-chain CLI tests to confirm no regression**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_supply_chain_cli.py -v`
Expected: all PASS (the new options have defaults; existing invocations unaffected). If `--offline` changed default behavior for an existing assertion, that test mocked no network so OSV with zero pinned deps must still degrade cleanly — fix by ensuring `query_osv` returns `{}` for an empty/no-lockfile repo (already handled: `if not deps: return {}`).

- [ ] **Step 8: Commit**

```bash
git add gitexpose/cli_advanced.py tests/test_supply_chain_cli_v05.py
git commit -m "feat(v0.5): wire lock-file SCA + OSV + cyclonedx into supply-chain command"
```

---

## Task 11: Console rendering of vulnerable_dependency findings

**Files:**
- Modify: `gitexpose/cli_advanced.py` (the console branch of `supply_chain`, ~lines 894-925)
- Test: `tests/test_supply_chain_cli_v05.py` (append)

- [ ] **Step 1: Write failing test in `tests/test_supply_chain_cli_v05.py`** (append)

```python
@respx.mock
def test_console_renders_vulnerable_dependency(tmp_path):
    _write_repo(tmp_path)
    _mock_osv()
    runner = CliRunner()
    result = runner.invoke(cli, ["supply-chain", str(tmp_path), "-o", "console"])
    assert "vulnerable_dependency" in result.output or "GHSA-xxxx" in result.output
    assert "lodash" in result.output
    assert "4.17.21" in result.output   # fixed version surfaced
```

- [ ] **Step 2: Run to verify failure**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_supply_chain_cli_v05.py::test_console_renders_vulnerable_dependency -v`
Expected: FAIL (fixed version / GHSA id not in console output — the generic renderer omits vuln fields).

- [ ] **Step 3: Add a vulnerable_dependency console branch** — inside the `for f in findings:` console loop, after the existing `if f.get("attack_class") or f.get("atlas_technique"):` block and before the `if verify:` block, insert:

```python
                if ftype == "vulnerable_dependency":
                    vid = f.get("vuln_id", "?")
                    fix = f.get("fixed_version")
                    fixtxt = f"fix: {fix}" if fix else "no fix available"
                    flags = []
                    if f.get("direct"):
                        flags.append("direct")
                    if not f.get("pinned"):
                        flags.append("unpinned")
                    if f.get("cred_co_present"):
                        flags.append("⚠ creds-co-present")
                    if f.get("known_exploited"):
                        flags.append("KEV")
                    cvss = f.get("cvss_score")
                    cvss_txt = f" CVSS {cvss}" if cvss else ""
                    flagtxt = f" [{', '.join(flags)}]" if flags else ""
                    lines.append(
                        f"     🔗 {f.get('package')}@{f.get('version')} — {vid}{cvss_txt} ({fixtxt}){flagtxt}"
                    )
```

- [ ] **Step 4: Run the test to verify pass**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_supply_chain_cli_v05.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add gitexpose/cli_advanced.py tests/test_supply_chain_cli_v05.py
git commit -m "feat(v0.5): console rendering for vulnerable_dependency findings"
```

---

## Task 12: v0.5 smoke test

**Files:**
- Create: `tests/fixtures/synthetic_repo_v05/requirements.txt`, `tests/test_smoke_v05.py`

- [ ] **Step 1: Create fixture `tests/fixtures/synthetic_repo_v05/requirements.txt`**

```
requests==2.19.0
lodash-fake-not-real==1.0.0
```

- [ ] **Step 2: Write smoke test `tests/test_smoke_v05.py`**

```python
"""v0.5 smoke: lock-file SCA + OSV (mocked) + cyclonedx, end to end.

Uses a recorded OSV fixture so the test is deterministic and offline-safe in CI.
The live-network smoke is performed manually before release (see plan Task 14).
"""

import json
from pathlib import Path

import httpx
import respx
from click.testing import CliRunner

from gitexpose.cli_advanced import cli

FIX = Path(__file__).parent / "fixtures" / "synthetic_repo_v05"
QUERYBATCH = "https://api.osv.dev/v1/querybatch"


@respx.mock
def test_smoke_v05_sca_and_bom():
    # requests 2.19.0 has known CVEs; mock OSV to return one deterministically.
    respx.post(QUERYBATCH).mock(return_value=httpx.Response(
        200, json={"results": [{"vulns": [{"id": "GHSA-req0"}]}, {}]}))
    respx.get("https://api.osv.dev/v1/vulns/GHSA-req0").mock(return_value=httpx.Response(
        200, json={"id": "GHSA-req0", "summary": "CRLF in requests",
                   "aliases": ["CVE-2018-18074"], "database_specific": {"severity": "HIGH"},
                   "affected": [{"ranges": [{"type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}))
    runner = CliRunner()

    # JSON path → vulnerable_dependency present
    res_json = runner.invoke(cli, ["supply-chain", str(FIX), "-o", "json"])
    findings = json.loads(res_json.output)
    assert any(f["type"] == "vulnerable_dependency" and f["package"] == "requests"
               for f in findings)

    # BOM path → valid CycloneDX with the component + VEX
    res_bom = runner.invoke(cli, ["supply-chain", str(FIX), "-o", "cyclonedx"])
    doc = json.loads(res_bom.output)
    assert doc["specVersion"] == "1.6"
    assert any(c["name"] == "requests" for c in doc["components"])


@respx.mock
def test_smoke_v05_offline_no_network():
    route = respx.post(QUERYBATCH)
    runner = CliRunner()
    res = runner.invoke(cli, ["supply-chain", str(FIX), "--offline", "-o", "json"])
    assert not route.called
    assert res.exit_code in (0, 1)
```

- [ ] **Step 3: Run the smoke test**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/test_smoke_v05.py -v`
Expected: both PASS.

- [ ] **Step 4: Run the FULL suite to confirm no regressions**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green (290 prior + new v0.5 tests). Investigate and fix any red before continuing.

- [ ] **Step 5: Commit**

```bash
git add tests/test_smoke_v05.py tests/fixtures/synthetic_repo_v05/
git commit -m "test(v0.5): end-to-end smoke (SCA + OSV mock + BOM + offline)"
```

---

## Task 13: Documentation, CHANGELOG, planning notes

**Files:**
- Modify: `README.md`, `docs/COVERAGE.md`, `CHANGELOG.md`
- Create: `docs/v0.5-planning-notes.md`

- [ ] **Step 1: Update `README.md`**

- Bump the version badge to `0.5.0`.
- Add a row to the threat-category table:
  `| **Live dependency SCA** (v0.5) | Lock-file parsing (Python + JS) + OSV.dev live CVE/GHSA lookups → `vulnerable_dependency` findings, ranked by exploitability context (direct/unpinned/fix-available/credential-co-presence), not raw CVSS. |`
- Add a row:
  `| **AI-BOM** (v0.5) | CycloneDX 1.6 security BOM (`--output cyclonedx`) with components, dependency-vulnerability VEX, and NTIA minimum elements. |`
- Add a "Supply-Chain Intelligence (v0.5)" section with examples:

```bash
# Live SCA (OSV on by default) + AI-BOM export
gitexpose supply-chain ./repo
gitexpose supply-chain ./repo -o cyclonedx --out-file sbom.cdx.json
# Air-gapped / offline (curated list only, no network)
gitexpose supply-chain ./repo --offline
```

- [ ] **Step 2: Update `docs/COVERAGE.md`** — add `vulnerable_dependency` to the finding-type matrix with its OWASP A06 / CICD-SEC-3 mapping, and note the Python+JS lock-file formats covered.

- [ ] **Step 3: Add a `CHANGELOG.md` v0.5.0 section**

```markdown
## [0.5.0] — 2026-05-28 — "Supply-Chain Intelligence"

### Added
- **Live dependency SCA**: lock-file parsing for Python (`requirements.txt`,
  `poetry.lock`, `Pipfile.lock`) and JavaScript (`package-lock.json`, `yarn.lock`),
  enriched via OSV.dev live CVE/GHSA lookups. New `vulnerable_dependency` finding type.
- **OSV.dev integration**: default on (sends package names + versions only),
  `--offline` opt-out falls back to the curated known-bad list. Bounded batch fan-out.
- **CycloneDX 1.6 AI-BOM**: `--output cyclonedx` (alias `aibom`) emits a security BOM
  with components, dependency-vulnerability VEX, and NTIA minimum elements.
- **Exploitability-first ranking**: dependency findings ordered by exploitability
  context (direct / unpinned / fix-available / credential-co-presence), CVSS secondary.

### Notes
- New core deps: `cyclonedx-python-lib`, `packageurl-python` (both pure-Python);
  `tomli` only on Python 3.9/3.10.
```

- [ ] **Step 4: Create `docs/v0.5-planning-notes.md`** — record the v0.6 backlog:

```markdown
# GitExpose v0.5 — Planning Notes

Shipped v0.5.0 "Supply-Chain Intelligence": lock-file SCA (Python+JS) + OSV.dev +
CycloneDX AI-BOM with honest VEX + exploitability-first ranking.

## v0.6 backlog (deferred from v0.5)
- Classic typosquatting (Levenshtein/Jaro-Winkler/homoglyph/keyboard) vs popular baselines.
- Lock-file POISONING checks: SRI hash mismatch, ghost deps, off-registry resolved URLs.
  (v0.5 already CAPTURES integrity_hash + resolved_url on every Dependency — cheap to add.)
- Shai-Hulud install-time behavioral analysis (lifecycle hooks, cred-harvest AST, metadata SSRF).
- Go (`go.sum`) + Cargo (`Cargo.lock`) ecosystems.
- Capability/scope enumeration for verified credentials.
- Policy engine + tamper-evident audit log.
- AI canary tokens (separate sister project).
```

- [ ] **Step 5: Run the full suite once more, then commit**

Run: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -m pytest tests/ -q`
Expected: all green.

```bash
git add README.md docs/COVERAGE.md CHANGELOG.md docs/v0.5-planning-notes.md
git commit -m "docs(v0.5): README + COVERAGE + CHANGELOG + v0.6 planning notes"
```

---

## Task 14: Manual live-network smoke (pre-release gate)

> This is a MANUAL step performed by the maintainer before tagging — same gated
> pattern as v0.2–v0.4. Not a pytest test (it hits the live OSV.dev API).

- [ ] **Step 1: Build a tiny repo with a genuinely-vulnerable pinned dep**

```bash
mkdir /tmp/ge-v05-smoke && printf 'requests==2.19.0\nlodash==0\n' > /tmp/ge-v05-smoke/requirements.txt
```

- [ ] **Step 2: Run live SCA (real OSV.dev)**

Run: `gitexpose supply-chain /tmp/ge-v05-smoke -o console`
Expected: at least one `vulnerable_dependency` for `requests@2.19.0` (it has real CVEs), with a fixed version and exploitability flags. Confirm the OSV egress notice prints to stderr.

- [ ] **Step 3: Run the BOM + offline paths**

Run: `gitexpose supply-chain /tmp/ge-v05-smoke -o cyclonedx --out-file /tmp/ge-v05-smoke/sbom.cdx.json`
Then validate: `/Library/Frameworks/Python.framework/Versions/3.12/bin/python3 -c "import json,sys; d=json.load(open('/tmp/ge-v05-smoke/sbom.cdx.json')); print(d['specVersion'], len(d['components']), len(d.get('vulnerabilities',[])))"`
Expected: `1.6`, ≥1 component, ≥1 vulnerability.

Run: `gitexpose supply-chain /tmp/ge-v05-smoke --offline -o console`
Expected: no network call; curated-only results.

- [ ] **Step 4: If all green, the release is ready** — follow the v0.4 ship procedure (tag `v0.5.0`, push branch + tag + main; the auto-release workflow builds wheel+sdist; set the release body with `gh release edit v0.5.0 --notes-file ...`). Watch for GitHub Push Protection on any new fixture cred values.

---

## Self-Review (completed during planning)

**1. Spec coverage** — every spec section maps to a task:
- §2 lock-file parsing → Tasks 3, 4, 5 (Python + JS + dispatcher)
- §2/§4 OSV default-on + `--offline` + bounded fan-out → Tasks 7, 10
- §5 `vulnerable_dependency` finding + OWASP A06 mapping + CVSS bucket → Tasks 6, 8
- §6 exploitability discipline + ordering → Task 8 (`exploitability_sort_key`), Task 11 (console), Task 9 (VEX state)
- §7 CycloneDX BOM + VEX + NTIA elements → Task 9
- §8 dependencies → Task 1
- §9 error handling (OSV degrade, parse-error skip, missing-lib msg) → Tasks 2, 7, 10
- §10 testing (parsers, OSV, mapping, reporter, smoke) → every task's tests + Task 12
- §11 docs/release → Tasks 13, 14
- §12 v0.6 backlog → Task 13 (`docs/v0.5-planning-notes.md`)

**2. Placeholder scan** — no TBD/TODO; every code step shows complete code; the one library-API caveat (Task 9 NOTE) gives the exact fallback call.

**3. Type consistency** — `Dependency`/`Vulnerability` fields are used identically across Tasks 3/4/7/8/9; `query_osv` signature (`deps, *, timeout, concurrency, max_deps`) matches its callers in Tasks 7 and 10; `build_vuln_findings(osv_map, deps, *, unpinned_packages, cred_sources)` matches Tasks 8 and 10; `build_bom(deps, findings)` matches Tasks 9 and 10; `exploitability_sort_key` used in Tasks 8 and 10. CLI `--output` choices include `cyclonedx`/`aibom` consistently in Tasks 10 and 11.

**Known risk:** `cyclonedx-python-lib` import names can differ across major versions (Task 9 NOTE addresses this with the documented `make_outputter` path). Verify against the installed version during Task 9 and adjust imports if needed.
