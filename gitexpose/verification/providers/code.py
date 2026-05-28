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
