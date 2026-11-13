"""Digest helpers, including Subresource Integrity (SRI) strings as used by npm."""

import base64
import hashlib

_SRI_ALGORITHMS = ("sha512", "sha384", "sha256")


class IntegrityError(ValueError):
    """Downloaded content does not match its advertised digest."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_integrity(data: bytes, *, integrity: str | None, shasum: str | None = None) -> str:
    """Check `data` against an SRI string (strongest supported algorithm wins) or, failing that,
    a legacy SHA-1 hex digest. Returns the algorithm used. Raises IntegrityError on mismatch or
    when no usable digest is given."""
    check = IntegrityCheck(integrity=integrity, shasum=shasum)
    check.update(data)
    return check.verify()


class IntegrityCheck:
    """`verify_integrity` over data that arrives in pieces (a streamed download): `update` with
    each piece, then `verify`. The algorithm is chosen up front, so a digest string with no
    usable algorithm fails at once, before anything is read."""

    def __init__(self, *, integrity: str | None, shasum: str | None = None) -> None:
        self._expected: list[str] = []
        self.algorithm = ""
        if integrity:
            candidates: dict[str, list[str]] = {}
            for token in integrity.split():
                algo, _, digest = token.partition("-")
                candidates.setdefault(algo, []).append(digest)
            for algo in _SRI_ALGORITHMS:
                if algo in candidates:
                    self.algorithm, self._expected = algo, candidates[algo]
                    break
        if not self.algorithm and shasum:
            self.algorithm, self._expected = "sha1", [shasum.lower()]
        if not self.algorithm:
            raise IntegrityError("no supported digest to verify against")
        self._hash = hashlib.new(self.algorithm, usedforsecurity=self.algorithm != "sha1")

    def update(self, data: bytes) -> None:
        self._hash.update(data)

    def verify(self) -> str:
        """The algorithm used; raises IntegrityError on a mismatch."""
        if self.algorithm == "sha1":
            actual = self._hash.hexdigest()
        else:
            actual = base64.b64encode(self._hash.digest()).decode()
        if actual not in self._expected:
            raise IntegrityError(f"{self.algorithm} digest mismatch")
        return self.algorithm
