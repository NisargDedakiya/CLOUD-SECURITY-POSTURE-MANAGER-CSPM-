"""Tool 6 — Cloud Security Posture Manager (CSPM).

A multi-cloud (AWS, GCP, Azure) security posture manager that mounts as a
router at ``/api/v1/cspm/`` on the shared Track 2 SaaS platform backend.

Modules (built in spec order):
    6.1  connectors  — cloud account connector (read-only, least privilege)
    6.2  auditors    — AWS security audit engine (class-based check_* methods)
    6.3  compliance  — CIS / SOC2 / ISO27001 / PCI-DSS mapping + scoring
    6.4  drift       — baseline snapshot + deep-diff continuous drift detection
"""

__version__ = "0.3.0"
