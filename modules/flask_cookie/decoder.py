
"""
Decode Dead - Flask Session Cookie Decoder

Decodes the payload of Flask's default signed session cookie.
This module does NOT verify the cookie signature.
"""

import base64
import binascii
import json
import zlib

from flask.json.tag import TaggedJSONSerializer


def decode_cookie_payload(cookie: str) -> dict:
    """
    Decode a Flask session cookie payload without verifying
    its signature.

    Supports Flask's URL-safe Base64 payload and optional
    zlib compression marker.

    Returns decoded payload and explicit verification status.
    """
    if not isinstance(cookie, str):
        raise ValueError("Cookie must be a string.")

    cookie = cookie.strip()

    if not cookie:
        raise ValueError("Cookie cannot be empty.")

    # Flask compressed cookies start with a dot:
    # .payload.timestamp.signature
    compressed = cookie.startswith(".")

    if compressed:
        cookie = cookie[1:]

    parts = cookie.split(".")

    if len(parts) != 3:
        raise ValueError(
            "Expected a Flask session cookie with 3 segments."
        )

    payload_segment = parts[0]
    timestamp_segment = parts[1]
    signature_segment = parts[2]

    if not payload_segment:
        raise ValueError("Cookie payload is empty.")

    try:
        padded = payload_segment + "=" * (
            -len(payload_segment) % 4
        )
        raw = base64.b64decode(
            padded,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid Base64URL payload.") from exc

    if compressed:
        try:
            raw = zlib.decompress(raw)
        except zlib.error as exc:
            raise ValueError(
                "Payload has a compression marker but "
                "could not be decompressed."
            ) from exc

    try:
        payload = TaggedJSONSerializer().loads(
            raw.decode("utf-8")
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ValueError(
            "Decoded payload is not valid Flask session JSON."
        ) from exc

    if not isinstance(payload, dict):
        raise ValueError(
            "Flask session payload must be a JSON object."
        )

    return {
        "payload": payload,
        "compressed": compressed,
        "timestamp": timestamp_segment,
        "signature": signature_segment,
        "signature_verified": False,
        "message": (
            "Payload decoded. Cookie signature has NOT "
            "been verified."
        ),
    }


def display_cookie(decoded: dict) -> None:
    """Display decoded Flask cookie information."""
    print("\n--- Decode Dead: Flask Cookie Decoder ---")

    print("\n[Session Payload]")
    print(json.dumps(
        decoded["payload"],
        indent=4,
        ensure_ascii=False,
    ))

    print("\n[Metadata]")
    print(f"Compressed: {decoded['compressed']}")
    print(f"Timestamp segment: {decoded['timestamp']}")
    print(f"Signature: {decoded['signature']}")
    print(
        f"Signature verified: "
        f"{decoded['signature_verified']}"
    )
    print(decoded["message"])

    print("========================================\n")