import base64
import hashlib

import pytest

from conftest import sri_sha512
from kitsunox.util.hashing import IntegrityError, verify_integrity


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
