"""Post-processor: paired-secret cluster + multi-provider-key file flagging.

Runs over the flat list of finding-dicts emitted by SecretExtractor and the
supply-chain scanners. Adds two new finding types alongside originals:

  - credential_cluster:           >=2 distinct secret types in same file
  - multi_provider_credential_file: cluster appears in a known aggregator path
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List

# Paths whose names indicate purpose-built multi-provider credential aggregators.
# A cluster finding in these gets upgraded to multi_provider_credential_file.
_MULTI_PROVIDER_AGGREGATORS = (
    re.compile(r"(^|/)OAI_CONFIG_LIST(\.|$)"),
    re.compile(r"(^|/)litellm[_-]?config\.(yaml|yml|json)$", re.IGNORECASE),
    re.compile(r"(^|/)\.continue/agents/.*\.yaml$"),
)

# Identify which finding dicts represent secrets vs other finding types.
_SECRET_TYPES_PREFIX_HINTS = (
    "_api_key",
    "_token",
    "_pat",
    "_webhook",
    "_key",
    "_sid",
    "_password",
    "private_key",
    "jwt_token",
)


def _is_secret(finding: Dict) -> bool:
    t = finding.get("type", "")
    return any(t.endswith(h) or t == h.lstrip("_") for h in _SECRET_TYPES_PREFIX_HINTS)


def _is_aggregator_path(source: str) -> bool:
    return any(p.search(source or "") for p in _MULTI_PROVIDER_AGGREGATORS)


def process(findings: List[Dict]) -> List[Dict]:
    """Return original findings plus any cluster/multi-provider findings."""
    by_source: Dict[str, List[Dict]] = defaultdict(list)
    for f in findings:
        if _is_secret(f):
            by_source[f.get("source", "")].append(f)

    additions: List[Dict] = []
    for source, secrets in by_source.items():
        types = sorted({s.get("type") for s in secrets if s.get("type")})
        if len(types) < 2:
            continue
        cluster = {
            "type": "credential_cluster",
            "source": source,
            "severity": "CRITICAL",
            "attack_class": "LLM06",
            "atlas_technique": "AML.T0019",
            "member_types": types,
            "member_findings": secrets,
            "description": (
                f"{len(types)} distinct secret types co-occur in {source}. "
                "Blast-radius: compromise of this file leaks credentials for "
                "multiple providers simultaneously."
            ),
        }
        additions.append(cluster)
        if _is_aggregator_path(source):
            additions.append({
                "type": "multi_provider_credential_file",
                "source": source,
                "severity": "CRITICAL",
                "attack_class": "LLM06",
                "atlas_technique": "AML.T0019",
                "member_types": types,
                "description": (
                    f"{source} is a known multi-provider credential aggregator path "
                    f"and contains {len(types)} distinct secret types. Single point "
                    "of compromise for the entire AI provider matrix."
                ),
            })

    return findings + additions
