"""Slither integration placeholder."""

from __future__ import annotations


def slither_available() -> bool:
    try:
        import slither  # noqa: F401
    except Exception:
        return False
    return True
