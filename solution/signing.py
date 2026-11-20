"""Simulated signature scheme.

The task calls for *simulated* verification records rather than real
cryptography.  The scheme still has the properties the trust algebra depends
on:

* a signature is bound to the exact canonical document bytes (a payload
  digest), to the document type, and to the tenant domain;
* a signature is bound to a ``key_id`` and a key *generation* so revocation
  can void individual generations;
* every signature carries a unique ``nonce`` so a replayed signature record
  can be recognised instead of being accepted a second time;
* the verifier only uses key material from its own trusted keyring, never
  from a document under verification.

A signature is HMAC-SHA256 over::

    b"SIMUPD|v1|" + doc_type + b"|" + tenant + b"|" + payload_digest + b"|" + nonce

where ``payload_digest`` is the canonical-JSON digest of the document with its
``signatures`` member removed.  Keyring entries map ``key_id`` to a 32-byte
secret (64 lowercase hex characters).
"""

from __future__ import annotations

import hashlib
import hmac
import re

from .canonical import canonical_json, digest_json, sha256_hex
from .errors import UpdateError, E_SIGNATURE_BAD_DIGEST, E_SIGNATURE_INVALID

DOMAIN = b"SIMUPD|v1|"
_SECRET_HEX = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:|@+-]{0,159}$")


def payload_of(doc: dict) -> dict:
    """The signed view of a document: everything except its signatures."""
    return {k: v for k, v in doc.items() if k != "signatures"}


def payload_digest(doc: dict) -> str:
    return digest_json(payload_of(doc))


def payload_bytes(doc: dict) -> bytes:
    return canonical_json(payload_of(doc))


def _message(doc_type: str, tenant: str, digest: str, nonce: str) -> bytes:
    return (
        DOMAIN
        + doc_type.encode("utf-8")
        + b"|"
        + tenant.encode("utf-8")
        + b"|"
        + digest.encode("ascii")
        + b"|"
        + nonce.encode("ascii")
    )


def sign(doc: dict, key_id: str, gen: int, secret_hex: str, nonce: str) -> dict:
    """Produce one signature record for ``doc`` (does not mutate the doc)."""
    if not _SECRET_HEX.match(secret_hex or ""):
        raise UpdateError(E_SIGNATURE_INVALID, "secret must be 32 bytes of lowercase hex", {"key_id": key_id})
    if not isinstance(nonce, str) or not _NONCE.match(nonce):
        raise UpdateError(E_SIGNATURE_INVALID, "nonce is missing or malformed", {"key_id": key_id})
    dg = payload_digest(doc)
    mac = hmac.new(
        bytes.fromhex(secret_hex),
        _message(doc["doc_type"], doc["tenant"], dg, nonce),
        hashlib.sha256,
    ).hexdigest()
    return {"key_id": key_id, "gen": int(gen), "nonce": nonce, "payload_digest": dg, "sig": mac}


def verify(doc: dict, record: dict, secret_hex: str) -> None:
    """Raise an ``E_SIGNATURE_*`` error unless ``record`` signs ``doc``."""
    if not isinstance(record, dict):
        raise UpdateError(E_SIGNATURE_INVALID, "signature record must be an object")
    key_id = record.get("key_id")
    gen = record.get("gen")
    nonce = record.get("nonce")
    claimed = record.get("payload_digest")
    mac = record.get("sig")
    if not isinstance(key_id, str) or not key_id:
        raise UpdateError(E_SIGNATURE_INVALID, "signature lacks key_id")
    if not isinstance(gen, int) or isinstance(gen, bool) or gen < 1:
        raise UpdateError(E_SIGNATURE_INVALID, "signature gen must be a positive integer", {"key_id": key_id})
    if not isinstance(nonce, str) or not _NONCE.match(nonce):
        raise UpdateError(E_SIGNATURE_INVALID, "signature lacks a well-formed nonce", {"key_id": key_id})
    actual = payload_digest(doc)
    if claimed != actual:
        raise UpdateError(
            E_SIGNATURE_BAD_DIGEST,
            "signature is bound to a different document digest",
            {"key_id": key_id, "claimed": claimed, "actual": actual},
        )
    if not _SECRET_HEX.match(secret_hex or ""):
        raise UpdateError(E_SIGNATURE_INVALID, "keyring entry is malformed", {"key_id": key_id})
    expected = hmac.new(
        bytes.fromhex(secret_hex),
        _message(doc["doc_type"], doc["tenant"], actual, nonce),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, mac if isinstance(mac, str) else ""):
        raise UpdateError(E_SIGNATURE_INVALID, "signature does not verify", {"key_id": key_id})


def key_fingerprint(secret_hex: str) -> str:
    """Stable public identifier for simulated key material."""
    return sha256_hex(bytes.fromhex(secret_hex))
