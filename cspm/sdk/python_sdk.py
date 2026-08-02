"""Aegis Python SDK (`cspm-sdk`).

Official Python client library for Aegis CNAPP & CSPM REST & GraphQL APIs.
"""

from __future__ import annotations

import requests


class AegisClient:
    """Python Client for Aegis CNAPP API."""

    def __init__(self, api_key: str, endpoint: str = "http://localhost:8000"):
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})

    def list_findings(self, status: str = "open") -> list[dict]:
        """Fetch open security findings."""
        url = f"{self.endpoint}/api/v1/cspm/findings?status={status}"
        resp = self.session.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def run_scan(self, account_id: str) -> dict:
        """Trigger instant security scan on a cloud account."""
        url = f"{self.endpoint}/api/v1/cspm/accounts/{account_id}/scan"
        resp = self.session.post(url, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def query_graphql(self, query: str) -> dict:
        """Execute GraphQL query."""
        url = f"{self.endpoint}/api/v1/graphql"
        resp = self.session.post(url, json={"query": query}, timeout=10)
        resp.raise_for_status()
        return resp.json()
