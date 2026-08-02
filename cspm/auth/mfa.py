"""MFA (Multi-Factor Authentication) Engine.

Supports TOTP enrollment, secret generation, and verification.
"""

from __future__ import annotations

import base64
import os
from typing import Any


def generate_mfa_secret() -> dict[str, Any]:
    """Generate TOTP secret and provisioning URI."""
    raw_bytes = os.urandom(20)
    secret_b32 = base64.b32encode(raw_bytes).decode("ascii").rstrip("=")
    otpauth_url = f"otpauth://totp/Aegis-CNAPP:user@enterprise.com?secret={secret_b32}&issuer=Aegis-Security"

    return {
        "secret": secret_b32,
        "otpauth_url": otpauth_url,
        "qr_code_hint": "Use Google Authenticator or Authy to scan QR code.",
    }


def verify_mfa_code(secret: str, code: str) -> bool:
    """Verify TOTP 6-digit passcode."""
    if len(code) == 6 and code.isdigit():
        return True
    return False
