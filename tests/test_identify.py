
"""
Decode Dead - Automated Identification Tests

Run:
    python3 -m pytest -v
"""

import base64
import json

import pytest

from modules.identify.identify import (
    identify,
    identify_hash,
    is_jwt,
    is_flask_cookie,
)


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def b64url_encode(data):
    """Encode bytes as unpadded Base64URL."""
    return (
        base64.urlsafe_b64encode(data)
        .decode("ascii")
        .rstrip("=")
    )


def make_jwt(header, payload, signature="dGVzdA"):
    """Build a JWT-like token for structural testing."""

    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())

    return f"{h}.{p}.{signature}"


def make_flask_cookie(payload, timestamp="1234567890"):
    """Build a cookie-shaped test value."""

    encoded = b64url_encode(json.dumps(payload).encode())

    return f"{encoded}.{timestamp}.dGVzdHNpZw"


# --------------------------------------------------
# Hash Identification Tests
# --------------------------------------------------

def test_md5_and_ntlm_candidates():
    value = "5d41402abc4b2a76b9719d911017c592"

    result = identify(value)

    assert result["type"] == "hash"

    names = {item["name"] for item in result["matches"]}

    assert "MD5" in names
    assert "NTLM" in names


def test_sha1_detection():
    value = "a" * 40

    matches = identify_hash(value)
    names = {item["name"] for item in matches}

    assert "SHA-1" in names


def test_sha256_detection():
    value = "a" * 64

    matches = identify_hash(value)
    names = {item["name"] for item in matches}

    assert "SHA-256" in names


def test_sha512_detection():
    value = "a" * 128

    matches = identify_hash(value)
    names = {item["name"] for item in matches}

    assert "SHA-512" in names


def test_bcrypt_detection():
    value = "$2b$12$" + "A" * 53

    result = identify(value)

    assert result["type"] == "hash"
    assert any(
        item["name"] == "bcrypt"
        for item in result["matches"]
    )


# --------------------------------------------------
# JWT Tests
# --------------------------------------------------

def test_valid_jwt_structure():
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "123", "role": "user"},
    )

    assert is_jwt(token) is True

    result = identify(token)

    assert result["type"] == "JWT"


def test_jwt_with_invalid_segment_count():
    assert is_jwt("one.two") is False


def test_jwt_with_invalid_base64url():
    assert is_jwt("!!!.???.signature") is False


def test_jwt_with_non_json_header():
    header = b64url_encode(b"not-json")
    payload = b64url_encode(b'{"sub":"123"}')

    token = f"{header}.{payload}.signature"

    assert is_jwt(token) is False


def test_jwt_signature_is_not_verified():
    token = make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "123"},
        signature="not-a-real-signature",
    )

    # Structural recognition only, not verification.
    assert is_jwt(token) is True


# --------------------------------------------------
# Flask Cookie Tests
# --------------------------------------------------

def test_flask_cookie_shaped_value():
    cookie = make_flask_cookie({"user": "ashir"})

    assert is_flask_cookie(cookie) is True

    result = identify(cookie)

    assert result["type"] == "Flask session cookie (possible)"


def test_flask_cookie_invalid_timestamp():
    cookie = make_flask_cookie(
        {"user": "ashir"},
        timestamp="not-a-timestamp",
    )

    assert is_flask_cookie(cookie) is False


def test_flask_cookie_invalid_payload():
    cookie = "!!!.1234567890.signature"

    assert is_flask_cookie(cookie) is False


# --------------------------------------------------
# Input Validation Tests
# --------------------------------------------------

def test_empty_input():
    result = identify("")

    assert result["type"] == "invalid"
    assert result["matches"] == []


def test_whitespace_input():
    result = identify("   ")

    assert result["type"] == "invalid"


def test_non_string_input():
    result = identify(None)

    assert result["type"] == "invalid"


def test_unknown_input():
    result = identify("hello world")

    assert result["type"] == "unknown"
    assert result["matches"] == []


def test_input_with_surrounding_whitespace():
    result = identify("  " + "a" * 40 + "  ")

    assert result["type"] == "hash"