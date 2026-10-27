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
    if integrity:
        candidates: dict[str, list[str]] = {}
        for token in integrity.split():
            algo, _, digest = token.partition("-")
            candidates.setdefault(algo, []).append(digest)
        for algo in _SRI_ALGORITHMS:
            if algo in candidates:
                actual = base64.b64encode(hashlib.new(algo, data).digest()).decode()
                if actual in candidates[algo]:
                    return algo
                raise IntegrityError(f"{algo} digest mismatch")
    if shasum:
        if hashlib.sha1(data, usedforsecurity=False).hexdigest() == shasum.lower():
            return "sha1"
        raise IntegrityError("sha1 digest mismatch")
    raise IntegrityError("no supported digest to verify against")
