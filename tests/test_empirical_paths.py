"""Tests for v0.2 empirical AI-tool config path additions."""

from gitexpose.paths_extended import get_extended_paths


def _all_path_strings():
    return {p.path for p in get_extended_paths()}


def test_continue_dev_paths_present():
    paths = _all_path_strings()
    assert ".continue/agents/new-config.yaml" in paths or any(
        p.startswith(".continue/agents/") for p in paths
    )
    assert any(p.startswith(".continue/config") for p in paths)


def test_claude_credentials_path_present():
    assert "claude/.credentials.json" in _all_path_strings()


def test_litellm_paths_present():
    assert any("litellm" in p.lower() for p in _all_path_strings())


def test_mcp_config_paths_present():
    assert "mcp.json" in _all_path_strings() or ".cursor/mcp.json" in _all_path_strings()


def test_dotnet_build_output_paths_present():
    assert any("bin/Debug" in p or "bin/Release" in p for p in _all_path_strings())


def test_drizzle_config_present():
    assert "drizzle.config.ts" in _all_path_strings()


def test_crewai_paths_present():
    paths = _all_path_strings()
    assert "agents.yaml" in paths
    assert "tasks.yaml" in paths


def test_autogen_oai_config_list_present():
    assert "OAI_CONFIG_LIST" in _all_path_strings()


def test_env_backup_variants_present():
    paths = _all_path_strings()
    assert any(p.endswith(".env.bak") or ".env." in p for p in paths)
