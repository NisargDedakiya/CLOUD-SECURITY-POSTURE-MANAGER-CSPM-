"""Tests for AES-256 encryption and Module 6.1 connectors."""

import json

import pytest

from cspm.connectors import ConnectorError, get_connector
from cspm.connectors.aws import AWSConnector
from cspm.security.crypto import decrypt, encrypt, generate_key


def test_encrypt_roundtrip():
    secret = "super-secret-value-123"
    token = encrypt(secret)
    assert token != secret
    assert decrypt(token) == secret


def test_encrypt_is_nondeterministic():
    # Random nonce → same plaintext yields different ciphertext.
    assert encrypt("x") != encrypt("x")


def test_generate_key_is_32_bytes():
    import base64

    assert len(base64.urlsafe_b64decode(generate_key())) == 32


def test_aws_connector_validates_with_injected_session():
    from cspm.fakes import FakeAWSSession

    conn = AWSConnector(role_arn="arn:aws:iam::123:role/audit", session=FakeAWSSession())
    result = conn.validate()
    assert result.ok
    assert result.account_identifier == "123456789012"
    assert result.stored_fields["role_arn"].endswith("role/audit")
    assert result.stored_fields["external_id"]  # auto-generated


def test_aws_connector_requires_role_arn():
    with pytest.raises(ConnectorError):
        AWSConnector(role_arn="")


def test_gcp_connector_encrypts_key():
    sa = json.dumps({"client_email": "x@y.iam", "project_id": "proj-1", "private_key": "k"})
    conn = get_connector("gcp", service_account_json=sa, validator=lambda info: None)
    result = conn.validate()
    assert result.account_identifier == "proj-1"
    enc = result.stored_fields["gcp_sa_key_enc"]
    assert json.loads(decrypt(enc))["project_id"] == "proj-1"


def test_gcp_connector_rejects_bad_json():
    conn = get_connector("gcp", service_account_json="{not json", validator=lambda i: None)
    with pytest.raises(ConnectorError):
        conn.validate()


def test_azure_connector_encrypts_secret():
    conn = get_connector(
        "azure",
        tenant_id="t1",
        client_id="c1",
        client_secret="shh",
        validator=lambda t, c, s: None,
    )
    result = conn.validate()
    assert result.account_identifier == "t1"
    assert decrypt(result.stored_fields["azure_secret_enc"]) == "shh"


def test_azure_connector_stores_subscription_id():
    conn = get_connector(
        "azure",
        tenant_id="t1",
        client_id="c1",
        client_secret="shh",
        subscription_id="sub-123",
        validator=lambda t, c, s: None,
    )
    result = conn.validate()
    assert result.stored_fields["azure_subscription_id"] == "sub-123"


def test_unsupported_provider():
    with pytest.raises(ConnectorError):
        get_connector("oracle")
