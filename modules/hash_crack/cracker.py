
"""
Decode Dead - Local Wordlist Cracker

Uses a wordlist such as rockyou.txt to test password candidates
against one or more supported hash algorithms.
"""

from pathlib import Path

from modules.hash_crack.algorithms import verify_hash


# Resolve the project root from this file's location.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Default wordlist stored inside the project.
DEFAULT_WORDLIST = PROJECT_ROOT / "wordlists" / "rockyou.txt"


def get_wordlist_path(wordlist_path=None):
    """Return the selected wordlist path."""
    if wordlist_path:
        return Path(wordlist_path).expanduser()

    return DEFAULT_WORDLIST


def validate_wordlist(wordlist_path):
    """Check that the wordlist exists and is a non-empty file."""
    path = Path(wordlist_path).expanduser()

    if not path.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Wordlist path is not a file: {path}"
        )

    if not path.stat().st_size:
        raise ValueError(
            f"Wordlist is empty: {path}"
        )

    return path


def normalize_algorithms(algorithms):
    """Normalize one algorithm or a collection of algorithms."""
    if isinstance(algorithms, str):
        algorithms = [algorithms]

    if not algorithms:
        raise ValueError(
            "At least one algorithm must be provided."
        )

    normalized = []

    for algorithm in algorithms:
        if not isinstance(algorithm, str) or not algorithm.strip():
            raise ValueError(
                "Algorithm names must be non-empty strings."
            )

        name = algorithm.strip().lower().replace("-", "_")

        if name not in normalized:
            normalized.append(name)

    return normalized


def crack_hash(
    target_hash,
    algorithms,
    wordlist_path=None,
    encoding="utf-8",
):
    """
    Try wordlist candidates against the supplied hash.

    Returns a dictionary containing:
        status, password, algorithm, attempts, wordlist
    """
    if not isinstance(target_hash, str) or not target_hash.strip():
        raise ValueError(
            "Target hash must be a non-empty string."
        )

    target_hash = target_hash.strip()
    algorithms = normalize_algorithms(algorithms)

    path = validate_wordlist(
        get_wordlist_path(wordlist_path)
    )

    attempts = 0

    try:
        with path.open(
            "r",
            encoding=encoding,
            errors="replace",
        ) as wordlist:

            for line in wordlist:
                candidate = line.rstrip("\r\n")

                if not candidate:
                    continue

                attempts += 1

                for algorithm in algorithms:
                    try:
                        matched = verify_hash(
                            candidate,
                            target_hash,
                            algorithm,
                        )
                    except (ValueError, RuntimeError):
                        # Skip unsupported algorithms or missing
                        # optional dependencies.
                        continue

                    if matched:
                        return {
                            "status": "found",
                            "password": candidate,
                            "algorithm": algorithm,
                            "attempts": attempts,
                            "wordlist": str(path),
                        }

    except PermissionError as exc:
        raise PermissionError(
            f"Cannot read wordlist: {path}"
        ) from exc

    return {
        "status": "not_found",
        "password": None,
        "algorithm": None,
        "attempts": attempts,
        "wordlist": str(path),
    }


def display_result(result):
    """Print a readable cracking result."""
    print("\n--- Decode Dead: Cracking Result ---")
    print(f"Status: {result['status']}")
    print(f"Attempts: {result['attempts']}")
    print(f"Wordlist: {result['wordlist']}")

    if result["status"] == "found":
        print(f"Password: {result['password']}")
        print(f"Algorithm: {result['algorithm']}")
    else:
        print("Password not found in this wordlist.")


if __name__ == "__main__":
    print("Decode Dead - Local Wordlist Cracker")

    target = input("Enter target hash: ").strip()
    algorithm = input(
        "Enter algorithm (e.g. md5, sha256, ntlm): "
    ).strip()

    custom_path = input(
        "Wordlist path (Enter for project rockyou.txt): "
    ).strip()

    try:
        result = crack_hash(
            target_hash=target,
            algorithms=algorithm,
            wordlist_path=custom_path or None,
        )
        display_result(result)

    except (ValueError, FileNotFoundError, PermissionError) as exc:
        print(f"[!] Error: {exc}")