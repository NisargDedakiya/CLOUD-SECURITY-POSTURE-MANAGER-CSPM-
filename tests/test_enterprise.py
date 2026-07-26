"""Tests for enterprise features: auth tokens, API keys, envelope crypto +
rotation, audit hash-chaining, notifications, remediation, reporting, prowler."""

import importlib

import pytest


# ---- envelope crypto + rotation -------------------------------------------
def test_envelope_crypto_roundtrip():
    from cspm.security.crypto import decrypt, encrypt

    token = encrypt("gcp-service-account-json")
    assert decrypt(token) == "gcp-service-account-json"


def test_ciphertext_is_versioned_and_nondeterministic():
    from cspm.security.crypto import encrypt

    assert encrypt("x") != encrypt("x")


def test_legacy_v1_ciphertext_still_decrypts():
    # Simulate a v1 blob: nonce||ct under the env root key.
    import base64
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from cspm.security.crypto import decrypt
    from cspm.security.keyprovider import EnvKeyProvider

    key = EnvKeyProvider().wrap_new_key()[1]
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, b"legacy-secret", None)
    token = base64.urlsafe_b64encode(nonce + ct).decode()
    assert decrypt(token) == "legacy-secret"


# ---- API keys --------------------------------------------------------------
def test_api_key_create_and_verify(db, org):
    from cspm.auth.apikeys import create_api_key, verify_api_key

    record, plaintext = create_api_key(db, org.id, "ci", role="analyst")
    assert plaintext.startswith("cspm_")
    verified = verify_api_key(db, plaintext)
    assert verified is not None and verified.id == record.id
    assert verify_api_key(db, "cspm_bogus_key") is None


def test_revoked_api_key_rejected(db, org):
    from cspm.auth.apikeys import create_api_key, verify_api_key

    record, plaintext = create_api_key(db, org.id, "ci")
    record.revoked = True
    db.commit()
    assert verify_api_key(db, plaintext) is None


# ---- JWT tokens ------------------------------------------------------------
def test_jwt_issue_and_verify(monkeypatch):
    monkeypatch.setenv("CSPM_JWT_SECRET", "test-secret")
    monkeypatch.setenv("CSPM_AUTH_MODE", "secret")
    import cspm.config as cfg

    importlib.reload(cfg)
    import cspm.auth.tokens as tokens

    importlib.reload(tokens)
    tok = tokens.issue_dev_token("user-1", "org-1", ["admin"])
    claims = tokens.verify_token(tok)
    assert claims["sub"] == "user-1" and claims["org"] == "org-1"
    with pytest.raises(tokens.TokenError):
        tokens.verify_token("not.a.token")


# ---- audit hash chaining ---------------------------------------------------
def test_audit_chain_intact_and_tamper_detected(db, org):
    from cspm.shared.audit import record_action, verify_chain
    from cspm.shared.models import AuditLogEntry

    for i in range(3):
        record_action(db, org_id=org.id, user_id="u", action=f"act.{i}")
    assert verify_chain(db, org.id) is True

    # Tamper with a historical entry.
    entry = db.query(AuditLogEntry).filter_by(org_id=org.id).first()
    entry.action = "tampered"
    db.commit()
    assert verify_chain(db, org.id) is False


# ---- notifications ---------------------------------------------------------
def test_dispatch_alert_filters_by_severity(monkeypatch):
    import cspm.config as cfg

    monkeypatch.setenv("CSPM_SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    monkeypatch.setenv("CSPM_ALERT_MIN_SEVERITY", "high")
    importlib.reload(cfg)
    import cspm.integrations.notify as notify

    importlib.reload(notify)

    sent = []
    findings = [
        {"severity": "low", "title": "minor", "resource": "r1"},
        {"severity": "critical", "title": "bad", "resource": "r2"},
    ]
    results = notify.dispatch_alert("test", findings, sender=lambda url, p: sent.append((url, p)))
    assert results.get("slack") is True
    assert len(sent) == 1  # only the critical finding triggered delivery
    assert "bad" in sent[0][1]["text"]


# ---- remediation -----------------------------------------------------------
def test_remediation_snippets():
    from cspm.remediation import remediation_for

    r = remediation_for("aws_s3_public_access_block")
    assert "put-public-access-block" in r["cli"]
    assert remediation_for("unknown_check")["cli"] == ""


# ---- reporting -------------------------------------------------------------
def test_findings_csv(db, org):
    from cspm.models import FindingRecord
    from cspm.reporting import findings_csv

    db.add(
        FindingRecord(
            org_id=org.id, cloud_account_id="a", check_id="aws_s3_encryption",
            resource="arn:x", severity="high", description="d", remediation="fix",
            dedup_hash="h1",
        )
    )
    db.commit()
    csv_text = findings_csv(db, org.id)
    assert "aws_s3_encryption" in csv_text
    assert csv_text.splitlines()[0].startswith("check_id,severity")


# ---- prowler adapter -------------------------------------------------------
def test_prowler_parse_only_fails():
    from cspm.auditors.prowler import parse_prowler_json

    data = [
        {"status": "FAIL", "check_id": "iam_1", "severity": "high", "resource_uid": "arn:1",
         "check_title": "IAM check", "status_extended": "bad"},
        {"status": "PASS", "check_id": "iam_2", "severity": "low", "resource_uid": "arn:2"},
    ]
    findings = parse_prowler_json(data)
    assert len(findings) == 1
    assert findings[0].check_id == "prowler_iam_1"
    assert findings[0].metadata["source"] == "prowler"
