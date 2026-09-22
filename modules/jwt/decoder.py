
"""
Decode Dead - JWT Decoder

Decodes JWT header and payload for inspection.
This module does NOT verify JWT signatures.
"""

import base64
import json
import re


BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]*$")


def decode_base64url(segment):
    """Decode a Base64URL segment into bytes."""
    if not isinstance(segment, str):
        raise ValueError("JWT segment must be a string.")

    if not segment:
        raise ValueError("JWT segment cannot be empty.")

    if not BASE64URL_PATTERN.fullmatch(segment):
        raise ValueError("Invalid Base64URL characters.")

    # JWT Base64URL segments may omit padding.
    padded = segment + "=" * (-len(segment) % 4)

    try:
        return base64.urlsafe_b64decode(padded)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Invalid Base64URL encoding.") from exc


def decode_json_segment(segment, segment_name):
    """Decode a Base64URL segment and parse it as a JSON object."""
    raw = decode_base64url(segment)

    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"{segment_name} is not valid UTF-8."
        ) from exc

    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{segment_name} is not valid JSON."
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"{segment_name} must be a JSON object."
        )

    return data


def decode_jwt(token):
    """
    Decode a compact JWT without verifying its signature.

    Returns:
        dict containing header, payload, signature,
        algorithm, and verification status.

    Raises:
        ValueError for malformed tokens.
    """
    if not isinstance(token, str):
        raise ValueError("JWT must be a string.")

    token = token.strip()

    if not token:
        raise ValueError("JWT cannot be empty.")

    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError(
            "JWT must contain exactly 3 segments."
        )

    header_segment, payload_segment, signature_segment = parts

    header = decode_json_segment(
        header_segment,
        "JWT header",
    )

    payload = decode_json_segment(
        payload_segment,
        "JWT payload",
    )

    # Signature is encoded data; it is not verified here.
    if signature_segment and not BASE64URL_PATTERN.fullmatch(
        signature_segment
    ):
        raise ValueError(
            "JWT signature contains invalid Base64URL characters."
        )

    return {
        "valid_structure": True,
        "header": header,
        "payload": payload,
        "signature": signature_segment,
        "algorithm": header.get("alg"),
        "type": header.get("typ"),
        "signature_verified": False,
        "message": (
            "JWT decoded successfully. "
            "Signature has NOT been verified."
        ),
    }


def display_jwt(decoded):
    """Print decoded JWT information in a readable format."""
    print("\n--- Decode Dead: JWT Decoder ---")

    print("\n[Header]")
    print(json.dumps(
        decoded["header"],
        indent=4,
        ensure_ascii=False,
    ))

    print("\n[Payload]")
    print(json.dumps(
        decoded["payload"],
        indent=4,
        ensure_ascii=False,
    ))

    print("\n[Signature]")
    print(decoded["signature"] or "(empty signature)")

    print("\n[Metadata]")
    print(f"Algorithm: {decoded['algorithm']}")
    print(f"Type: {decoded['type']}")
    print(f"Structure valid: {decoded['valid_structure']}")
    print(f"Signature verified: {decoded['signature_verified']}")
    print(decoded["message"])





if __name__ == "__main__":
    print("Decode Dead - JWT Decoder")

    token = input("Enter JWT: ").strip()

    try:
        result = decode_jwt(token)
        display_jwt(result)

    except ValueError as exc:
        print(f"[!] Error: {exc}")