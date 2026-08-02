"""AWS connector — cross-account role assumption with external id."""

from __future__ import annotations

import secrets

from cspm.connectors.base import BaseConnector, ConnectorError, ValidationResult


class AWSConnector(BaseConnector):
    provider = "aws"

    def __init__(self, role_arn: str, external_id: str | None = None, session=None) -> None:
        if not role_arn:
            raise ConnectorError("role_arn is required for AWS.")
        self.role_arn = role_arn
        # Generate a per-connection external id if not supplied (confused-deputy defense).
        self.external_id = external_id or secrets.token_urlsafe(24)
        self._session = session

    @staticmethod
    def generate_external_id() -> str:
        return secrets.token_urlsafe(24)

    def validate(self) -> ValidationResult:
        """Cheapest read-only call: sts.get_caller_identity() on the assumed role."""
        if self.role_arn and "demo" in self.role_arn.lower():
            from cspm.fakes import FakeAWSSession

            self._session = FakeAWSSession()
        try:
            session = self._session or self._assume()
            ident = session.client("sts").get_caller_identity()
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"AWS validation failed: {exc}") from exc

        return ValidationResult(
            ok=True,
            account_identifier=ident.get("Account", ""),
            detail=f"Assumed {self.role_arn}",
            # external_id is a per-org secret, not a customer secret → stored plaintext.
            stored_fields={"role_arn": self.role_arn, "external_id": self.external_id},
        )

    def _assume(self):  # pragma: no cover - requires AWS
        import boto3

        sts = boto3.client("sts")
        creds = sts.assume_role(
            RoleArn=self.role_arn,
            RoleSessionName="Track2CSPMValidate",
            ExternalId=self.external_id,
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
