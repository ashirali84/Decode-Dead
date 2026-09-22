"""
Decode Dead - Hash Algorithms

Provides candidate hashing and verification for supported frokmats.
Hash identification and password verification are separate operations.
"""

import hashlib
import hmac
import re

# Fast, unsalted hash algorithms supported by hashlib.

HASHLIB_ALGORITHMS = {
    "md5": "md5",
    "sha1": "sha1",
    "sha224": "sha224",
     "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha3_256": "sha3_256",
    "sha3_512": "sha3_512",
    "ntlm": "md4",
}

def _validate_text(value, field_name):
    """Ensure inputs are non-empty strings."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")


def hash_candidate(password, algorithm):
    """
    Hash a candidate password using a supported fast hash.

    Note:
    NTLM hashes UTF-16LE encoded password bytes.
    Other algorithms use UTF-8.
    """
    _validate_text(password, "password")
    _validate_text(algorithm, "algorithm")

    algorithm = algorithm.lower()

    if algorithm not in HASHLIB_ALGORITHMS:
        raise ValueError(f"Unsupported fast hash: {algorithm}")

    if algorithm == "ntlm":
        data = password.encode("utf-16le")
    else:
        data = password.encode("utf-8")

    try:
        digest = hashlib.new(HASHLIB_ALGORITHMS[algorithm], data)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Hash algorithm unavailable: {algorithm}"
        ) from exc

    return digest.hexdigest()


def verify_fast_hash(password, expected_hash, algorithm):
    """Verify a candidate against a fast, unsalted hash."""
    _validate_text(expected_hash, "expected_hash")

    candidate_hash = hash_candidate(password, algorithm)

    return hmac.compare_digest(
        candidate_hash.lower(),
        expected_hash.strip().lower(),
    )


def verify_bcrypt(password, encoded_hash):
    """Verify a bcrypt hash, if bcrypt is installed."""
    _validate_text(password, "password")
    _validate_text(encoded_hash, "encoded_hash")

    try:
        import bcrypt
    except ImportError as exc:
        raise RuntimeError(
            "bcrypt is required. Install it with: pip install bcrypt"
        ) from exc

    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            encoded_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


def verify_argon2(password, encoded_hash):
    """Verify an encoded Argon2 hash, if argon2-cffi is installed."""
    _validate_text(password, "password")
    _validate_text(encoded_hash, "encoded_hash")

    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import (
            VerificationError,
            InvalidHashError,
        )
    except ImportError as exc:
        raise RuntimeError(
            "argon2-cffi is required. "
            "Install it with: pip install argon2-cffi"
        ) from exc

    try:
        return PasswordHasher().verify(encoded_hash, password)
    except (VerificationError, InvalidHashError, ValueError):
        return False


def verify_pbkdf2(password, encoded_hash):
    """
    Verify Werkzeug-style PBKDF2 hashes.

    Example:
    pbkdf2:sha256:600000$salt$hex_digest
    """
    _validate_text(password, "password")
    _validate_text(encoded_hash, "encoded_hash")

    try:
        from werkzeug.security import check_password_hash
    except ImportError as exc:
        raise RuntimeError(
            "Werkzeug is required. Install it with: pip install werkzeug"
        ) from exc

    try:
        return check_password_hash(encoded_hash, password)
    except (ValueError, TypeError):
        return False


def verify_unix_crypt(password, encoded_hash):
    """
    Verify Unix crypt hashes, when the platform supports crypt.

    Supports formats provided by the system crypt implementation,
    including SHA-256 and SHA-512 crypt where available.
    """
    _validate_text(password, "password")
    _validate_text(encoded_hash, "encoded_hash")

    try:
        import crypt
    except ImportError as exc:
        raise RuntimeError(
            "The crypt module is unavailable on this Python platform."
        ) from exc

    try:
        result = crypt.crypt(password, encoded_hash)
    except (ValueError, TypeError):
        return False

    if not result:
        return False

    return hmac.compare_digest(result, encoded_hash)


def verify_hash(password, expected_hash, algorithm):
    """
    Dispatch verification to the appropriate implementation.

    Returns:
        True  - candidate verified
        False - candidate did not match
    Raises:
        ValueError - invalid input or unsupported algorithm
        RuntimeError - required optional dependency unavailable
    """
    _validate_text(password, "password")
    _validate_text(expected_hash, "expected_hash")
    _validate_text(algorithm, "algorithm")

    algorithm = algorithm.lower().replace("-", "_")

    if algorithm in HASHLIB_ALGORITHMS:
        return verify_fast_hash(
            password,
            expected_hash,
            algorithm,
        )

    if algorithm == "bcrypt":
        return verify_bcrypt(password, expected_hash)

    if algorithm == "argon2":
        return verify_argon2(password, expected_hash)

    if algorithm in ("pbkdf2", "werkzeug_pbkdf2"):
        return verify_pbkdf2(password, expected_hash)

    if algorithm in ("unix_sha256", "unix_sha512", "unix_crypt"):
        return verify_unix_crypt(password, expected_hash)

    raise ValueError(f"Unsupported hash algorithm: {algorithm}")