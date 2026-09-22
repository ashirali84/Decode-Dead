"""

Decode Dead - Hash and Token Identification

Identify possible hash formats and common token structures.

Important:
This module performs format recognition only;

It does not prove the origin or authenticity of an input.
"""

import base64
import json
import re


from modules.identify.hash_patterns import get_hash_patterns


# --------------------------------------------------
# Base64 / JWT Helpers
# --------------------------------------------------


def decode_base64url(segment):
    """Decode a Base64URL segment into bytes."""

    if not segment:
        raise ValueError("Empty Base64URL segment")

    if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError("Invalid Base64URL characters")

    padded = segment + "=" * (-len(segment)%4)    

    return base64.urlsafe_b64decode(padded)

def is_json_bytes(data):
    """Check whether bytes contain Valid JSON."""    

    try:
        json.loads(data.decode("utf-8"))
        return True
    except (ValueError, UnicodeDecodeError):
        return False

def is_jwt(token):
    """
    Recognize a JWT-like three-segment structure.

    this checks the Structure and JSON header/payload.
    It does not verify the signature.
    """    

    parts = token.split(".")

    if len(parts) !=3:
        return False

    try:
        header = decode_base64url(parts[0])
        payload = decode_base64url(parts[1])

        header_obj = json.loads(header.decode("utf-8"))
        payload_obj = json.loads(payload.decode("utf-8"))

        return (
            isinstance(header_obj, dict)
            and isinstance(payload_obj, dict)
        )
    except (ValueError, UnicodeDecodeError):
        return False


# --------------------------------------------------
# Flask Session Cookie Heuristic
# --------------------------------------------------


def is_flask_cookie(token):
    """
    Heuristically recognize common Flask signed-session
    cookie structure

    This is not proof that a cookie came from Flask
    """

    #comman Flask session cookie structure:
    # payload.timestamp.signature

    parts = token.split(".")

    if len(parts) not in (2,3):
        return False

    payload = parts[0]

    # Flask session payload commonly uses Base64URL

    try:
        decoded = decode_base64url(payload)

        if not is_json_bytes(decoded):
            return False
        
    except (ValueError, UnicodeDecodeError):
        return False

    # Three-part cookies often have a timestamp segment.
    if len(parts) == 3:
        timestamp = parts[1]

        if not re.fullmatch(r"\d{1,12}", timestamp):
            return False
        signature = parts[2]

        if not re.fullmatch(r"[A-Za-z0-9_-]+", signature):
            return False
        
        return True
    # Two-part structure is only weak heuristic
    return True

# --------------------------------------------------
# Hash Identification
# --------------------------------------------------


def identify_hash(value):
    matches = []

    for item in get_hash_patterns():
        if re.fullmatch(item["regex"], value):
            matches.append({
                "name": item["name"],
                "category": item["category"],
                "description": item["description"],
                "ambiguous": item["ambiguous"],
            })

    return matches

# --------------------------------------------------
# Main Identification Function
# --------------------------------------------------

def identify(value):
    """
    Identify a possible token or hash format.

    Returns a dictionary containing:
        input
        type
        matches
        message
    """

    if not isinstance(value, str):
        return {
            "input": value,
            "type": "invalid",
            "matches": [],
            "message": "Input must be a string.",
        }

    value = value.strip()

    if not value:
        return {
            "input": value,
            "type": "invalid",
            "matches": [],
            "message": "Input cannot be empty.",
        }

    # JWT detection first because it is a structured token.
    if is_jwt(value):
        return {
            "input": value,
            "type": "JWT",
            "matches": ["JSON Web Token"],
            "message": (
                "JWT-like structure detected. "
                "Signature has not been verified."
            ),
        }

    # Flask cookie heuristic.
    if is_flask_cookie(value):
        return {
            "input": value,
            "type": "Flask session cookie (possible)",
            "matches": ["Flask signed-session format"],
            "message": (
                "Possible Flask session cookie structure. "
                "Origin and signature are unverified."
            ),
        }

    # Hash pattern matching.
    matches = identify_hash(value)

    if matches:
        return {
            "input": value,
            "type": "hash",
            "matches": matches,
            "message": (
                "Possible hash format(s) found. "
                "Exact algorithm is not guaranteed."
            ),
        }

    return {
        "input": value,
        "type": "unknown",
        "matches": [],
        "message": "No supported format matched.",
    }




