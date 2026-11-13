import base64
import hashlib

import pytest

from conftest import sri_sha512
from kitsunox.util.hashing import IntegrityCheck, IntegrityError, verify_integrity


def test_sri_match() -> None:
    assert verify_integrity(b"data", integrity=sri_sha512(b"data")) == "sha512"


def test_sri_mismatch() -> None:
    with pytest.raises(IntegrityError, match="sha512"):
        verify_integrity(b"tampered", integrity=sri_sha512(b"data"))


def test_strongest_algorithm_is_checked() -> None:
    # A matching weak digest must not rescue a mismatching strong one.
    weak = "sha256-" + base64.b64encode(hashlib.sha256(b"x").digest()).decode()
    with pytest.raises(IntegrityError):
        verify_integrity(b"x", integrity=f"{weak} {sri_sha512(b'other')}")


def test_falls_back_to_sha1_shasum() -> None:
    shasum = hashlib.sha1(b"data", usedforsecurity=False).hexdigest()
    assert verify_integrity(b"data", integrity=None, shasum=shasum) == "sha1"
    with pytest.raises(IntegrityError):
        verify_integrity(b"other", integrity=None, shasum=shasum)


def test_no_digest_is_an_error() -> None:
    with pytest.raises(IntegrityError, match="no supported digest"):
        verify_integrity(b"data", integrity="md5-abc")


@pytest.mark.parametrize(
    ("integrity", "shasum"),
    [
        (sri_sha512(b"data"), None),
        ("sha256-" + base64.b64encode(hashlib.sha256(b"data").digest()).decode(), None),
        (None, hashlib.sha1(b"data", usedforsecurity=False).hexdigest()),
        ("md5-unsupported", hashlib.sha1(b"data", usedforsecurity=False).hexdigest()),
    ],
)
def test_integrity_check_in_pieces_agrees_with_verify_integrity(
    integrity: str | None, shasum: str | None
) -> None:
    check = IntegrityCheck(integrity=integrity, shasum=shasum)
    for piece in (b"d", b"", b"ata"):
        check.update(piece)
    assert check.verify() == verify_integrity(b"data", integrity=integrity, shasum=shasum)
    wrong = IntegrityCheck(integrity=integrity, shasum=shasum)
    wrong.update(b"dat")
    with pytest.raises(IntegrityError, match="mismatch"):
        wrong.verify()


def test_integrity_check_without_a_digest_fails_before_reading() -> None:
    with pytest.raises(IntegrityError, match="no supported digest"):
        IntegrityCheck(integrity="md5-x", shasum=None)
