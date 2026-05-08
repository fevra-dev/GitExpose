"""Tests for unpinned AI middleware detection."""

from pathlib import Path

from gitexpose.advanced.dependency_pinning import DependencyPinningScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_requirements_has_no_findings():
    text = (FIXTURES / "requirements_clean.txt").read_text()
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    assert findings == []


def test_unpinned_ai_middleware_flagged():
    text = (FIXTURES / "requirements_unpinned.txt").read_text()
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    types = {f["type"] for f in findings}
    assert "unpinned_ai_middleware" in types
    flagged_packages = {f["package"] for f in findings}
    assert flagged_packages == {"litellm", "langchain", "openai", "crewai"}


def test_each_finding_has_severity_and_metadata():
    text = (FIXTURES / "requirements_unpinned.txt").read_text()
    findings = DependencyPinningScanner().scan(text, source="requirements.txt")
    for f in findings:
        assert f["severity"] == "HIGH"
        assert f["attack_class"] == "LLM05"
        assert f["atlas_technique"] == "AML.T0019"


def test_non_ai_packages_unpinned_are_not_flagged():
    """unpinned `requests` is real-world bad practice but not an AI-middleware risk."""
    findings = DependencyPinningScanner().scan(
        "requests\nflask\n", source="requirements.txt"
    )
    assert findings == []
