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
