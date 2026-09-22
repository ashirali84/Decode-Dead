
"""
Decode Dead - Hash Pattern Database

Stores recognizable hash formats and their basic patterns.

Note:
A matching pattern suggests a possible algorithm.
It does not prove which algorithm generated the hash.
"""

HASH_PATTERNS = [
    {
        "name": "MD5",
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "category": "fast_hash",
        "description": "128-bit MD5 digest",
        "ambiguous": True,
    },
    {
        "name": "NTLM",
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "category": "password_hash",
        "description": "Windows NT password hash",
        "ambiguous": True,
    },
    {
        "name": "SHA-1",
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "category": "fast_hash",
        "description": "160-bit SHA-1 digest",
        "ambiguous": False,
    },
    {
        "name": "SHA-224",
        "length": 56,
        "regex": r"^[a-fA-F0-9]{56}$",
        "category": "fast_hash",
        "description": "224-bit SHA-2 digest",
        "ambiguous": False,
    },
    {
        "name": "SHA-256",
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "category": "fast_hash",
        "description": "256-bit SHA-2 digest",
        "ambiguous": False,
    },
    {
        "name": "SHA-384",
        "length": 96,
        "regex": r"^[a-fA-F0-9]{96}$",
        "category": "fast_hash",
        "description": "384-bit SHA-2 digest",
        "ambiguous": False,
    },
    {
        "name": "SHA-512",
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "category": "fast_hash",
        "description": "512-bit SHA-2 digest",
        "ambiguous": False,
    },
    {
        "name": "SHA3-256",
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "category": "fast_hash",
        "description": "256-bit SHA-3 digest",
        "ambiguous": True,
    },
    {
        "name": "SHA3-512",
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "category": "fast_hash",
        "description": "512-bit SHA-3 digest",
        "ambiguous": True,
    },
    {
        "name": "bcrypt",
        "length": 60,
        "regex": r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$",
        "category": "password_hash",
        "description": "bcrypt password hash",
        "ambiguous": False,
    },
    {
        "name": "Argon2",
        "length": None,
        "regex": (
            r"^\$argon2(id|i|d)\$"
            r"v=\d+\$m=\d+,t=\d+,p=\d+"
            r"(\$[A-Za-z0-9+/]+)?"
            r"\$[A-Za-z0-9+/]+$"
        ),
        "category": "password_hash",
        "description": "Argon2 encoded password hash",
        "ambiguous": False,
    },
    {
        "name": "PBKDF2",
        "length": None,
        "regex": (
            r"^pbkdf2:"
            r"(sha1|sha256|sha384|sha512)"
            r":\d+\$[^$]+\$[A-Za-z0-9+/=]+$"
        ),
        "category": "password_hash",
        "description": "Werkzeug-style PBKDF2 hash",
        "ambiguous": False,
    },
    {
        "name": "Unix SHA-256 Crypt",
        "length": None,
        "regex": r"^\$5\$(rounds=\d+\$)?[^$]+\$[./A-Za-z0-9]{1,}$",
        "category": "password_hash",
        "description": "SHA-256 crypt password hash",
        "ambiguous": False,
    },
    {
        "name": "Unix SHA-512 Crypt",
        "length": None,
        "regex": r"^\$6\$(rounds=\d+\$)?[^$]+\$[./A-Za-z0-9]{1,}$",
        "category": "password_hash",
        "description": "SHA-512 crypt password hash",
        "ambiguous": False,
    },
    {
        "name": "PHPass",
        "length": 34,
        "regex": r"^\$P\$[./A-Za-z0-9]{31}$",
        "category": "password_hash",
        "description": "Portable PHP password hash",
        "ambiguous": False,
    },
]


def get_hash_patterns():
    """Return the registered hash pattern definitions."""
    return HASH_PATTERNS