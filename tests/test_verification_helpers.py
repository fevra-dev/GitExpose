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
