
import pytest

from modules.hash_crack.algorithms import hash_candidate
from modules.hash_crack.cracker import crack_hash


@pytest.fixture
def wordlist(tmp_path):
    """Create a temporary wordlist for testing."""
    path = tmp_path / "test_words.txt"
    path.write_text(
        "wrongpass\nhello123\nadmin\n",
        encoding="utf-8",
    )
    return path


def test_password_found(wordlist):
    target = hash_candidate("hello123", "md5")

    result = crack_hash(
        target_hash=target,
        algorithms=["md5"],
        wordlist_path=wordlist,
    )

    assert result["status"] == "found"
    assert result["password"] == "hello123"
    assert result["algorithm"] == "md5"
    assert result["attempts"] == 2


def test_password_not_found(wordlist):
    target = hash_candidate("not-in-list", "md5")

    result = crack_hash(
        target_hash=target,
        algorithms=["md5"],
        wordlist_path=wordlist,
    )

    assert result["status"] == "not_found"
    assert result["password"] is None
    assert result["attempts"] == 3


def test_multiple_algorithms(wordlist):
    target = hash_candidate("admin", "sha256")

    result = crack_hash(
        target_hash=target,
        algorithms=["md5", "sha256"],
        wordlist_path=wordlist,
    )

    assert result["status"] == "found"
    assert result["password"] == "admin"
    assert result["algorithm"] == "sha256"


def test_missing_wordlist(tmp_path):
    missing_path = tmp_path / "missing.txt"
    target = hash_candidate("hello123", "md5")

    with pytest.raises(FileNotFoundError):
        crack_hash(
            target_hash=target,
            algorithms=["md5"],
            wordlist_path=missing_path,
        )


def test_empty_wordlist(tmp_path):
    empty_path = tmp_path / "empty.txt"
    empty_path.write_text("", encoding="utf-8")

    target = hash_candidate("hello123", "md5")

    with pytest.raises(ValueError, match="empty"):
        crack_hash(
            target_hash=target,
            algorithms=["md5"],
            wordlist_path=empty_path,
        )


@pytest.mark.parametrize(
    "target",
    ["", "   ", None, 123],
)
def test_invalid_target_hash(wordlist, target):
    with pytest.raises(ValueError):
        crack_hash(
            target_hash=target,
            algorithms=["md5"],
            wordlist_path=wordlist,
        )


def test_no_algorithm_provided(wordlist):
    target = hash_candidate("hello123", "md5")

    with pytest.raises(ValueError):
        crack_hash(
            target_hash=target,
            algorithms=[],
            wordlist_path=wordlist,
        )