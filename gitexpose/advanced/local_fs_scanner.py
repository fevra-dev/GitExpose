"""Local filesystem walker that powers the `supply-chain` CLI subcommand.

Walks a directory, applies SecretExtractor and supply-chain modules, returns
a flat list of finding-dicts (the same shape SecretExtractor.extract emits,
plus the supply-chain modules' shapes). Pure-local, no network.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Dict, Iterable, List

from ..secrets.secret_extractor import SecretExtractor
from .dependency_pinning import DependencyPinningScanner
from .known_bad_versions import scan_requirements as scan_known_bad
from .slopsquatting import scan_requirements as scan_slopsquats
from .supply_chain_patterns import scan_text as scan_supply_patterns

logger = logging.getLogger(__name__)

# Extensions to scan. Everything else is skipped.
_TEXT_EXTENSIONS = frozenset({
    ".py", ".yaml", ".yml", ".json", ".toml", ".md", ".txt",
    ".cfg", ".ini", ".sh", ".pth", ".env", ".js", ".ts", ".tsx",
})

# Directories never to descend into.
_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})

# Files matching these names are scanned even if extension isn't in _TEXT_EXTENSIONS.
_BARE_FILENAMES = frozenset({"OAI_CONFIG_LIST", "Dockerfile"})

_DEFAULT_MAX_BYTES = 1 * 1024 * 1024  # 1 MB


class LocalFilesystemScanner:
    """Walks a path and runs all v0.2 file-content scanners."""

    def __init__(self, max_bytes: int = _DEFAULT_MAX_BYTES):
        self.max_bytes = max_bytes
        self._secret_extractor = SecretExtractor()
        self._dep_pinning = DependencyPinningScanner()

    def scan(self, root: Path) -> List[Dict]:
        root = Path(root)
        findings: List[Dict] = []
        for path in self._iter_files(root):
            try:
                if path.stat().st_size > self.max_bytes:
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                logger.debug("Skipping unreadable file %s: %s", path, exc)
                continue
            if "\x00" in content[:1024]:
                continue  # binary
            relative = str(path.relative_to(root))
            findings.extend(self._scan_content(content, relative, path.name))
        return findings

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() in _TEXT_EXTENSIONS or path.name in _BARE_FILENAMES:
                yield path

    def _scan_content(self, content: str, relative: str, basename: str) -> List[Dict]:
        out: List[Dict] = []

        # Credential extraction (async — run via asyncio.run for sync API)
        try:
            secrets = asyncio.run(
                self._secret_extractor.extract(content, source=relative)
            )
            out.extend(secrets)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Secret extraction failed for %s: %s", relative, exc)

        # Dependency pinning + known-bad versions + slopsquatting (only for dep files)
        if basename in {"requirements.txt", "requirements-dev.txt"} or basename.startswith("requirements"):
            out.extend(self._dep_pinning.scan(content, source=relative))
            known_bad = scan_known_bad(content, source=relative)
            out.extend(known_bad)
            slop = scan_slopsquats(content, source=relative)
            # Dedup: if a (package, source) appears in both known_bad and slopsquatting,
            # known_malicious_package_version is more specific — drop the slopsquatting dup.
            known_bad_keys = {(f["package"], f["source"]) for f in known_bad}
            out.extend(
                f for f in slop
                if (f["package"], f["source"]) not in known_bad_keys
            )
        elif basename == "pyproject.toml" or basename == "package.json":
            # For these, only the dependency-pinning scanner is applicable; known-bad
            # and slopsquatting are requirements.txt-shaped only in v0.2.
            out.extend(self._dep_pinning.scan(content, source=relative))

        # Supply-chain patterns (any text file)
        out.extend(scan_supply_patterns(content, filename=basename, source=relative))

        return out
