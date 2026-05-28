"""AWS access+secret pairing: SecretExtractor emits access & secret as separate
findings; the engine must pair same-source ones into 'ACCESS:SECRET' for the
verifier, without clobbering value_full."""

import pytest
import respx
import httpx

from gitexpose.verification.engine import pair_aws_credentials, verify_secrets
from gitexpose.verification.result import VerificationStatus


def test_pair_aws_sets_verify_input_for_same_source():
    findings = [
        {"type": "aws_access_key", "value_full": "AKIAIOSFODNN7EXAMPLE", "source": ".env"},
        {"type": "aws_secret_key", "value_full": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "source": ".env"},
    ]
    pair_aws_credentials(findings)
    access = next(f for f in findings if f["type"] == "aws_access_key")
    assert access["_verify_input"] == "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert access["value_full"] == "AKIAIOSFODNN7EXAMPLE"


def test_pair_aws_skips_when_no_same_source_secret():
    findings = [
        {"type": "aws_access_key", "value_full": "AKIAIOSFODNN7EXAMPLE", "source": "a.env"},
        {"type": "aws_secret_key", "value_full": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "source": "b.env"},
    ]
    pair_aws_credentials(findings)
    access = next(f for f in findings if f["type"] == "aws_access_key")
    assert "_verify_input" not in access


@pytest.mark.asyncio
@respx.mock
async def test_verify_uses_paired_input_for_aws():
    respx.post("https://sts.amazonaws.com/").mock(
        return_value=httpx.Response(200, text="<GetCallerIdentityResponse></GetCallerIdentityResponse>")
    )
    findings = [
        {"type": "aws_access_key", "value_full": "AKIA" + "A" * 16, "source": ".env"},
        {"type": "aws_secret_key", "value_full": "x" * 40, "source": ".env"},
    ]
    pair_aws_credentials(findings)
    await verify_secrets(findings)
    access = next(f for f in findings if f["type"] == "aws_access_key")
    assert access["verification_status"] == VerificationStatus.VERIFIED.value
