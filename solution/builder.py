"""Deterministic synthesis of tenants, documents and dual-mirror packages.

Nothing here is trusted at run time - it *builds* the fixtures.  A case file
describes holders, keys, roots, snapshots, targets and payloads in a compact
declarative form; this module turns that description into real signed
documents with real digests, written into two byte-identical mirrors.

Every nonce is derived from ``(case, document identity, key id, generation)``
so rebuilding a case is byte-for-byte identical, while two different
documents never share a signature record unless the case says so.

Ordering inside a build step is deliberate:

1. assemble the document body,
2. apply ``tamper_before_sign`` (so a signature is *valid over bad content*),
3. sign with ``sign``,
4. apply ``tamper_after_sign`` (so the signature no longer matches).

That lets a negative case choose between "correctly signed but wrong content"
and "right content but broken signature".
"""

from __future__ import annotations

import copy
import os

from .canonical import canonical_json, digest_json, normalize_repo_path, sha256_hex, safe_join
from .docs import ZERO_DIGEST, doc_digest
from .signing import sign

PACKAGE_FORMAT = "simupd-package/1"


class BuildError(Exception):
    """A case description that cannot be synthesised."""


# --------------------------------------------------------------------------
# domain
# --------------------------------------------------------------------------
class Domain:
    """Tenant, holders and their simulated key material."""

    def __init__(self, spec: dict) -> None:
        self.tenant = spec["tenant"]
        self.holders: dict = {}
        self.secret_of: dict = {}
        self.role_of_holder: dict = {}
        for holder, info in spec["holders"].items():
            role = info["role"]
            keys = dict(info["keys"])
            if not keys:
                raise BuildError(f"holder {holder} has no keys")
            self.holders[holder] = keys
            self.role_of_holder[holder] = role
            for key_id, secret in keys.items():
                if key_id in self.secret_of and self.secret_of[key_id] != secret:
                    raise BuildError(f"key {key_id} is defined twice with different secrets")
                self.secret_of[key_id] = secret

    def holder_keys(self, holder: str) -> dict:
        if holder not in self.holders:
            raise BuildError(f"unknown holder {holder!r}")
        return self.holders[holder]

    def secret(self, holder: str, key_id: str) -> str:
        keys = self.holder_keys(holder)
        if key_id not in keys:
            raise BuildError(f"holder {holder} does not own key {key_id}")
        return keys[key_id]


# --------------------------------------------------------------------------
# session: remembers built artefacts so predecessors can be auto-linked
# --------------------------------------------------------------------------
class Session:
    def __init__(self, domain: Domain, case_name: str) -> None:
        self.domain = domain
        self.case_name = case_name
        self.roots: dict = {}       # version -> doc
        self.snapshots: dict = {}   # (channel, version) -> doc
        self.targets: dict = {}     # (target_id, version) -> doc
        self.payload_text: dict = {}

    # -- payloads ---------------------------------------------------------
    @staticmethod
    def payload_bytes(spec) -> bytes:
        if isinstance(spec, str):
            if spec.startswith("text:"):
                return spec[5:].encode("utf-8")
            if spec.startswith("hex:"):
                return bytes.fromhex(spec[4:])
            return spec.encode("utf-8")
        if isinstance(spec, dict):
            if "text" in spec:
                return spec["text"].encode("utf-8")
            if "hex" in spec:
                return bytes.fromhex(spec["hex"])
            if "repeat" in spec:
                byte_hex, count = spec["repeat"]
                return bytes.fromhex(byte_hex) * int(count)
        raise BuildError(f"unsupported payload spec: {spec!r}")

    # -- signing ----------------------------------------------------------
    def nonce(self, doc_key_text: str, key_id: str, gen: int) -> str:
        return f"{self.case_name}|{doc_key_text}|{key_id}|{gen}"

    def _signers(self, spec) -> list:
        signers = spec.get("sign") or []
        if not isinstance(signers, list):
            raise BuildError("sign must be a list of {holder, key, gen?} objects")
        return signers

    def _sign(self, doc: dict, signers: list, doc_key_text: str) -> None:
        records = []
        for signer in signers:
            holder = signer["holder"]
            key_id = signer["key"]
            gen = int(signer.get("gen", 1))
            secret = self.domain.secret(holder, key_id)
            nonce = signer.get("nonce") or self.nonce(doc_key_text, key_id, gen)
            record = sign(doc, key_id, gen, secret, nonce)
            if signer.get("corrupt_sig"):
                record["sig"] = "0" * 64
            if signer.get("wrong_digest"):
                record["payload_digest"] = "1" * 64
            records.append(record)
        if not signers:
            records = []
        doc["signatures"] = records

    @staticmethod
    def _apply(doc: dict, patch) -> None:
        if patch:
            doc.update(copy.deepcopy(patch))

    # -- roots ------------------------------------------------------------
    def build_root(self, spec: dict) -> dict:
        version = int(spec["version"])
        previous = self.roots.get(version - 1)
        if version > 1 and previous is None:
            raise BuildError(f"root v{version} needs v{version - 1} to link against")
        doc = {
            "doc_type": "root",
            "tenant": self.domain.tenant,
            "version": version,
            "previous_version": version - 1,
            "previous_digest": doc_digest(previous) if previous else ZERO_DIGEST,
            "issued_at": int(spec["issued_at"]),
            "expires_at": int(spec["expires_at"]),
            "roles": {
                role_name: self._policy(role_name, spec[role_name], spec.get("revoked", {}).get(role_name, []))
                for role_name in ("root", "snapshot", "target")
            },
        }
        doc["keyring"] = self._keyring(doc["roles"])
        self._apply(doc, spec.get("tamper_before_sign"))
        self._sign(doc, self._signers(spec), f"root|{version}")
        self._apply(doc, spec.get("tamper_after_sign"))
        self.roots[version] = doc
        return doc

    def _policy(self, role_name: str, spec: dict, revoked: list) -> dict:
        holders = list(spec["holders"])
        return {
            "threshold": int(spec["threshold"]),
            "holders": {holder: sorted(self.domain.holder_keys(holder)) for holder in holders},
            "revoked": [{"key_id": item["key"], "gen": int(item["gen"])} for item in revoked],
            "tags": list(spec.get("tags", ["*"])),
            "paths": list(spec.get("paths", ["*"])),
        }

    def _keyring(self, roles: dict) -> dict:
        keyring = {}
        for policy in roles.values():
            for keys in policy["holders"].values():
                for key in keys:
                    keyring[key] = self.domain.secret_of[key]
        return keyring

    # -- targets ----------------------------------------------------------
    def build_target(self, spec: dict) -> dict:
        target_id = spec["id"]
        version = int(spec["version"])
        previous = self.targets.get((target_id, version - 1))
        if version > 1 and previous is None:
            raise BuildError(f"target {target_id} v{version} needs v{version - 1}")
        content = self.payload_bytes(spec["payload"])
        doc = {
            "doc_type": "target",
            "tenant": self.domain.tenant,
            "target_id": target_id,
            "version": version,
            "previous_version": version - 1,
            "previous_digest": doc_digest(previous) if previous else ZERO_DIGEST,
            "root_version": int(spec["root_version"]),
            "snapshot_version": int(spec["snapshot_version"]),
            "channel": spec["channel"],
            "purpose": spec["purpose"],
            "repo_tag": spec["repo_tag"],
            "path": spec["path"],
            "file": {"digest": sha256_hex(content), "size": len(content)},
            "issued_at": int(spec["issued_at"]),
            "expires_at": int(spec["expires_at"]),
        }
        self._apply(doc, spec.get("tamper_before_sign"))
        self._sign(doc, self._signers(spec), f"target|{target_id}|{version}")
        self._apply(doc, spec.get("tamper_after_sign"))
        self.targets[(target_id, version)] = doc
        return doc

    # -- snapshots --------------------------------------------------------
    def build_snapshot(self, spec: dict, entries: list | None = None) -> dict:
        """Build a snapshot.

        ``entries`` overrides ``spec["entries"]`` when it carries any rows;
        an empty list falls back to the spec, because a snapshot with no
        entries is never useful and case files encode refs in the spec.
        """
        if not entries:
            entries = list(spec.get("entries", []))
        channel = spec["channel"]
        version = int(spec["version"])
        previous = self.snapshots.get((channel, version - 1))
        if version > 1 and previous is None:
            raise BuildError(f"snapshot {channel} v{version} needs v{version - 1}")
        doc = {
            "doc_type": "snapshot",
            "tenant": self.domain.tenant,
            "channel": channel,
            "version": version,
            "previous_version": version - 1,
            "previous_digest": doc_digest(previous) if previous else ZERO_DIGEST,
            "root_version": int(spec["root_version"]),
            "repo_tag": spec["repo_tag"],
            "issued_at": int(spec["issued_at"]),
            "expires_at": int(spec["expires_at"]),
            "entries": entries,
        }
        self._apply(doc, spec.get("tamper_before_sign"))
        self._sign(doc, self._signers(spec), f"snapshot|{channel}|{version}")
        self._apply(doc, spec.get("tamper_after_sign"))
        self.snapshots[(channel, version)] = doc
        return doc

    @staticmethod
    def make_entry(target_doc: dict, overrides: dict | None = None) -> dict:
        entry = {
            "target_id": target_doc["target_id"],
            "version": target_doc["version"],
            "purpose": target_doc["purpose"],
            "repo_tag": target_doc["repo_tag"],
            "path": target_doc["path"],
            "manifest_digest": doc_digest(target_doc),
            "file_digest": target_doc["file"]["digest"],
        }
        if overrides:
            entry.update(overrides)
        return entry


# --------------------------------------------------------------------------
# package writer
# --------------------------------------------------------------------------
def doc_rel_path(doc: dict) -> str:
    if doc["doc_type"] == "root":
        return f"roots/root-{doc['version']:04d}.json"
    if doc["doc_type"] == "snapshot":
        return f"snapshots/{doc['channel']}-{doc['version']:04d}.json"
    return f"targets/{doc['target_id']}-{doc['version']:04d}.json"


def write_package(
    package_dir: str,
    tenant: str,
    docs: list,
    files: dict,
    *,
    doc_rel_overrides: dict | None = None,
    omit_from_mirror: dict | None = None,
    mirror_override: dict | None = None,
    index_extra: dict | None = None,
    raw_doc_bytes: dict | None = None,
) -> str:
    """Write ``docs`` and ``files`` into two byte-identical mirrors."""
    mirrors = ("mirror-a", "mirror-b")
    omit_from_mirror = omit_from_mirror or {}
    mirror_override = mirror_override or {}
    doc_rel_overrides = doc_rel_overrides or {}
    raw_doc_bytes = raw_doc_bytes or {}

    for mirror in mirrors:
        os.makedirs(os.path.join(package_dir, mirror), exist_ok=True)

    index = {
        "format": PACKAGE_FORMAT,
        "tenant": tenant,
        "mirrors": list(mirrors),
        "documents": [],
        "files": [],
    }
    if index_extra:
        index.update(index_extra)

    payload: dict = {}
    for doc in docs:
        rel = doc_rel_overrides.get(id(doc)) or doc_rel_path(doc)
        payload[rel] = raw_doc_bytes.get(id(doc)) or canonical_json(doc)
        index["documents"].append(rel)
    for rel_path, content in files.items():
        normalize_repo_path(rel_path)
        payload[rel_path] = content
        index["files"].append(rel_path)
    index["documents"].sort()
    index["files"].sort()

    for mirror in mirrors:
        for rel_path, content in payload.items():
            if rel_path in omit_from_mirror.get(mirror, []):
                omit_from_mirror[mirror]  # keep the branch obvious
                continue
            data = mirror_override.get(mirror, {}).get(rel_path, content)
            dest = safe_join(os.path.join(package_dir, mirror), rel_path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as handle:
                handle.write(data)

    index_path = os.path.join(package_dir, "index.json")
    with open(index_path, "wb") as handle:
        handle.write(canonical_json(index))
    return package_dir


def package_digest_of(docs: list, files: dict) -> str:
    doc_map = {doc_rel_path(doc): sha256_hex(canonical_json(doc)) for doc in docs}
    file_map = {rel: sha256_hex(content) for rel, content in files.items()}
    return digest_json({"documents": doc_map, "files": file_map})
