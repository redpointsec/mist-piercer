# mpierce/generate.py
"""Guaranteed-nonexistent baseline generators.

Pure Python (uuid4) so values are: guaranteed non-existent, fresh per call,
and deterministic in shape (no LLM hallucination).
"""
import uuid


def _suffix() -> str:
    return uuid.uuid4().hex[:12]


def random_username(seed: str = "user") -> str:
    return f"{seed}{_suffix()}"


def random_email(seed: str = "user", domain: str = "example.com") -> str:
    return f"{seed}{_suffix()}@{domain}"


def random_numeric(width: int = 10) -> str:
    """A fresh numeric identifier of exactly `width` digits (best-effort
    non-existence — keep width realistic for the target's IDs)."""
    digits = uuid.uuid4().int   # 39-ish digit integer
    s = str(digits).lstrip("0") or "0"
    return (s * width)[:width] if len(s) < width else s[:width]
