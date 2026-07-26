"""Bounded pagination helpers.

List endpoints accept ``limit``/``offset`` and set an ``X-Total-Count`` header,
so responses stay plain arrays (backward-compatible) while queries are always
bounded — no accidental full-table scans.
"""

from __future__ import annotations

from fastapi import Query, Response

from cspm.config import get_settings

_settings = get_settings()


def limit_param() -> int:
    return Query(
        default=_settings.default_page_size,
        ge=1,
        le=_settings.max_page_size,
        description="Max rows to return.",
    )


def offset_param() -> int:
    return Query(default=0, ge=0, description="Rows to skip.")


def paginate(query, response: Response, limit: int, offset: int) -> list:
    """Apply limit/offset, set X-Total-Count, return the page."""
    total = query.order_by(None).count()
    response.headers["X-Total-Count"] = str(total)
    return query.limit(limit).offset(offset).all()
