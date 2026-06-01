# test/test_generate.py
import re
from mpierce.generate import random_username, random_email


def test_random_username_shape_and_freshness():
    a = random_username("bob")
    b = random_username("bob")
    assert a.startswith("bob")
    assert a != b                       # freshness per call
    assert re.fullmatch(r"bob[0-9a-f]{12}", a)  # name + 12-hex uuid suffix


def test_random_email_shape():
    e = random_email("alice")
    assert re.fullmatch(r"alice[0-9a-f]{12}@example\.com", e)


def test_random_email_custom_domain():
    e = random_email("alice", domain="rdpt.dev")
    assert e.endswith("@rdpt.dev")


def test_default_seed_when_none():
    u = random_username()
    assert re.fullmatch(r"user[0-9a-f]{12}", u)
