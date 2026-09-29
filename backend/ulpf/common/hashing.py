"""
Cryptographic hashing and hash-chain primitives for ULPF.

This module underpins the "Tamper-Evident Event Provenance" requirement
(PS ID: 26156, Section 10). It provides:

  * ``sha256_hex`` — deterministic SHA-256 of arbitrary content.
  * ``hash_chain_next`` — compute the next link in a hash chain
    ``H(previous_hash || current_hash)``.
  * ``compute_event_hash`` — canonical SHA-256 over an event's normalized
    representation (used to prove a normalized event still corresponds to its
    stored raw payload).

Important:
  * SHA-256 + hash chaining provides *tamper evidence*, NOT a blockchain.
    No blockchain is introduced here; the term is used only where an actual
    blockchain implementation exists.
  * Hashing is deterministic and order-independent of dict insertion for the
    canonical serialization, so verification is reproducible across services.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data`` (bytes)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("sha256_hex expects bytes input")
    return hashlib.sha256(data).hexdigest()


def sha256_str(text: str) -> str:
    """Return the lowercase hex SHA-256 digest of a UTF-8 string."""
    return sha256_hex(text.encode("utf-8"))


def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to a deterministic, sorted JSON byte string.

    Sorting keys and using compact separators guarantees that the same logical
    content always produces the same hash, regardless of dict insertion order.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def hash_chain_next(previous_hash: str, current_hash: str, seed: str | None = None) -> str:
    """Compute the next link of an event hash chain.

    The chain links an event to its predecessor so that any retroactive
    reordering or removal of events is detectable. Each link is:

        H(seed || previous_hash || current_hash)

    ``seed`` is an optional deployment-wide salt (from LINEAGE_HASH_SEED).
    """
    material = (seed or "") + (previous_hash or "") + (current_hash or "")
    return sha256_hex(material.encode("utf-8"))


def compute_event_hash(event_dict: Any, seed: str | None = None) -> str:
    """Compute a canonical SHA-256 over a normalized event's content.

    This represents the immutable fingerprint of *what was stored*; if the
    raw payload changes after storage, re-computing this hash yields a
    different value and the mismatch is detected as tampering.
    """
    return hash_chain_next(seed or "", "", sha256_hex(canonical_json(event_dict)))


def verify_event_hash(event_dict: Any, expected_hash: str, seed: str | None = None) -> bool:
    """Return True if recomputing the event hash matches ``expected_hash``."""
    actual = compute_event_hash(event_dict, seed=seed)
    # Constant-time comparison to avoid timing side-channels.
    if len(actual) != len(expected_hash or ""):
        return False
    result = 0
    for a, b in zip(actual, expected_hash or ""):
        result |= ord(a) ^ ord(b)
    return result == 0
