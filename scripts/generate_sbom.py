#!/usr/bin/env python3
"""Generate CycloneDX / SPDX Software Bill of Materials (SBOM)."""

import json
from datetime import UTC, datetime

def generate_sbom():
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:aegis-sbom-2026",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "name": "aegis-cnapp-platform",
                "version": "1.0.0",
                "type": "application"
            }
        },
        "components": [
            {"name": "fastapi", "version": "0.104.1", "purl": "pkg:pypi/fastapi@0.104.1"},
            {"name": "sqlalchemy", "version": "2.0.23", "purl": "pkg:pypi/sqlalchemy@2.0.23"},
            {"name": "cryptography", "version": "42.0.0", "purl": "pkg:pypi/cryptography@42.0.0"},
            {"name": "pydantic", "version": "2.5.2", "purl": "pkg:pypi/pydantic@2.5.2"}
        ]
    }
    print(json.dumps(sbom, indent=2))

if __name__ == "__main__":
    generate_sbom()
