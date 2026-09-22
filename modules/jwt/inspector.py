
from datetime import datetime, timezone
from typing import Any


TIME_CLAIMS = ("exp", "iat", "nbf")
STANDARD_CLAIMS = ("iss", "sub", "aud")


def format_timestamp(value: Any) -> str:
    """Convert a numeric Unix timestamp to readable UTC."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "Invalid timestamp"

    try:
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "Invalid timestamp"


def inspect_claims(payload: dict, now: float | None = None) -> dict:
    """
    Inspect common JWT claims.

    This function does NOT verify the JWT signature.
    `now` is injectable for deterministic tests.
    """
    if not isinstance(payload, dict):
        raise TypeError("JWT payload must be a dictionary")

    if now is None:
        now = datetime.now(timezone.utc).timestamp()

    result = {
        "time_claims": {},
        "standard_claims": {},
        "warnings": [],
        "signature_verified": False,
    }

    for claim in TIME_CLAIMS:
        if claim not in payload:
            result["time_claims"][claim] = {
                "present": False,
                "value": None,
                "readable": None,
                "status": "Not present",
            }
            continue

        value = payload[claim]
        readable = format_timestamp(value)

        if readable == "Invalid timestamp":
            status = "Invalid value"
            result["warnings"].append(
                f"{claim} must be a numeric Unix timestamp."
            )
        elif claim == "exp":
            status = "Expired" if now >= value else "Not expired"
        elif claim == "nbf":
            status = "Not yet valid" if now < value else "Valid now"
        else:  # iat
            status = "Issued in the future" if value > now else "Issued"

        result["time_claims"][claim] = {
            "present": True,
            "value": value,
            "readable": readable,
            "status": status,
        }

    for claim in STANDARD_CLAIMS:
        result["standard_claims"][claim] = {
            "present": claim in payload,
            "value": payload.get(claim),
        }

    return result


def display_claims(inspection: dict) -> None:
    """Print inspected JWT claims."""
    print("\n========== JWT CLAIMS ==========")

    print("\n[Time Claims]")
    for claim, details in inspection["time_claims"].items():
        print(f"\n{claim}:")
        print(f"  Present : {details['present']}")
        if details["present"]:
            print(f"  Value   : {details['value']}")
            print(f"  UTC     : {details['readable']}")
            print(f"  Status  : {details['status']}")

    print("\n[Standard Claims]")
    for claim, details in inspection["standard_claims"].items():
        print(f"{claim}: {details['value'] if details['present'] else 'Not present'}")

    if inspection["warnings"]:
        print("\n[Warnings]")
        for warning in inspection["warnings"]:
            print(f"- {warning}")

    print("\nSignature verified: No")
    print("Note: Claims inspection does not authenticate a JWT.")
    print("================================\n")


def inspect_decoded_jwt(decoded: dict) -> dict:
    """
    Inspect claims from the output of decode_jwt().
    Does not verify the JWT signature.
    """
    if not isinstance(decoded, dict):
        raise TypeError("Decoded JWT must be a dictionary")

    if not decoded.get("valid_structure"):
        raise ValueError("Cannot inspect an invalid JWT structure")

    payload = decoded.get("payload")

    if not isinstance(payload, dict):
        raise ValueError("JWT payload must be a dictionary")

    return inspect_claims(payload)    