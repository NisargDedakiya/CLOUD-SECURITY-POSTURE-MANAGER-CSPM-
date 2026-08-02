"""PDF/JSON Invoice Generator and Tax Calculation Engine.

Calculates GST (18% for India) or VAT (20% for EU/UK), generates invoice metadata,
and exports downloadable PDF and JSON invoice summaries.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from sqlalchemy.orm import Session
from cspm.models import InvoiceRecord


def generate_subscription_invoice(
    db: Session,
    org_id: str,
    plan_name: str = "Pro",
    amount: float = 299.0,
    currency: str = "USD",
    tax_region: str | None = "IN",  # IN (GST 18%), EU/UK (VAT 20%), US (0%)
) -> dict[str, Any]:
    """Generate invoice record with appropriate tax calculation."""
    tax_rate = 0.0
    tax_type = None

    if tax_region == "IN" or currency == "INR":
        tax_rate = 0.18
        tax_type = "GST (18%)"
    elif tax_region in ("EU", "UK", "GB"):
        tax_rate = 0.20
        tax_type = "VAT (20%)"

    tax_amount = round(amount * tax_rate, 2)
    total_amount = round(amount + tax_amount, 2)

    invoice_rec = InvoiceRecord(
        org_id=org_id,
        amount=total_amount,
        currency=currency,
        tax_amount=tax_amount,
        tax_type=tax_type,
        status="paid",
        pdf_url=f"/api/v1/cspm/billing/invoices/download/inv_{org_id[:8]}.pdf",
    )
    db.add(invoice_rec)
    db.commit()

    return {
        "invoice_id": invoice_rec.id,
        "org_id": org_id,
        "plan": plan_name,
        "subtotal": amount,
        "tax_type": tax_type,
        "tax_amount": tax_amount,
        "total_amount": total_amount,
        "currency": currency,
        "issued_at": datetime.now(UTC).isoformat(),
        "pdf_download_url": invoice_rec.pdf_url,
    }
