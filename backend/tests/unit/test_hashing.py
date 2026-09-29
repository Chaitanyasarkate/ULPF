"""Unit tests for the hashing and hash-chain lineage foundation."""

from __future__ import annotations

import pytest

from ulpf.common.hashing import (
    canonical_json,
    compute_event_hash,
    hash_chain_next,
    sha256_hex,
    sha256_str,
    verify_event_hash,
)


def test_sha256_hex_known_vector():
    # SHA-256 of empty string.
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    # SHA-256 of "abc".
    assert sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_str_matches_hex():
    assert sha256_str("abc") == sha256_hex(b"abc")


def test_sha256_hex_rejects_non_bytes():
    with pytest.raises(TypeError):
        sha256_hex("abc")


def test_canonical_json_is_deterministic():
    obj_a = {"b": 2, "a": 1}
    obj_b = {"a": 1, "b": 2}
    assert canonical_json(obj_a) == canonical_json(obj_b)


def test_canonical_json_handles_non_string_keys():
    data = {1: "x", 2: "y"}
    out = canonical_json(data)
    assert b"1" in out and b"x" in out


def test_hash_chain_is_chain_linked():
    link1 = sha256_hex(b"first")
    link2 = hash_chain_next("", link1, "")
    link3 = hash_chain_next(link1, link2, "")
    assert link2 != link3
    assert len(link3) == 64


def test_hash_chain_constant():
    link1 = sha256_hex(b"a")
    link2 = sha256_hex(b"b")
    # Same inputs => same chain link (deterministic).
    assert hash_chain_next(link1, link2) == hash_chain_next(link1, link2)


def test_compute_event_hash_is_stable():
    event = {"event_id": "abc", "ocsf": {"src_endpoint.ip": "1.2.3.4"}}
    h1 = compute_event_hash(event)
    h2 = compute_event_hash({"ocsf": {"src_endpoint.ip": "1.2.3.4"}, "event_id": "abc"})
    assert h1 == h2
    assert len(h1) == 64


def test_verify_event_hash_positive():
    event = {"event_id": "abc", "ocsf": {"src_endpoint.ip": "1.2.3.4"}}
    h = compute_event_hash(event)
    assert verify_event_hash(event, h) is True


def test_verify_event_hash_negative_on_tamper():
    event = {"event_id": "abc", "ocsf": {"src_endpoint.ip": "1.2.3.4"}}
    h = compute_event_hash(event)
    tampered = {"event_id": "abc", "ocsf": {"src_endpoint.ip": "9.9.9.9"}}
    assert verify_event_hash(tampered, h) is False


def test_verify_event_hash_rejects_wrong_length():
    assert verify_event_hash({"a": 1}, "short") is False


def test_hash_chain_with_seed_changes_output():
    base = hash_chain_next("a", "b", "")
    seeded = hash_chain_next("a", "b", "secret-seed")
    assert base != seeded
