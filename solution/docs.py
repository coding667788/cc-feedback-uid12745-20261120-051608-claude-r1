"""Document schemas, role-policy algebra and threshold evaluation.

Three signed document kinds exist: ``root``, ``snapshot`` and ``target``.
Only ``root`` documents carry key material.  A snapshot or target document is
always verified against the keyring of the *confirmed* root, never against
anything that appears inside the document itself.

Role policy
-----------
Each root defines three mutually exclusive roles.  A role policy is::

    {
      "threshold": int >= 1,
      "holders": {"holder-id": ["key-id", ...], ...},
      "revoked": [{"key_id": ..., "gen": int}, ...],
      "tags": ["core", ...] or ["*"],
      "paths": ["app", ...] or ["*"]
    }

Thresholds count *holders*, not keys: one holder presenting several keys
still occupies one seat.  A signature whose ``(key_id, gen)`` pair is revoked
by the policy is discarded before counting.  A key that belongs to a
different role is a hard error, not a silently ignored record.  Role
authorization is by repository tag plus path prefix; prefix matching is on
whole path segments, so ``app/x`` never authorizes ``app/xevil``.

Root rotation
-------------
A new root is signed by *both* the outgoing and the incoming root role, and
the two quorums must be filled by **different holders**.  Seat allocation is
a two-demand Hall feasibility problem: with ``A`` the old-side holders, ``B``
the new-side holders, ``k_old``/``k_new`` the thresholds, a valid disjoint
allocation exists iff ``|A| >= k_old``, ``|B| >= k_new`` and
``|A union B| >= k_old + k_new``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import digest_json, is_sha256_hex, normalize_repo_path, path_segments
from .errors import (
    E_INPUT_INVALID,
    E_PATH_ESCAPE,
    E_ROOT_DOC_INVALID,
    E_ROLE_EXCLUSIVITY,
    E_SIGNATURE_INVALID,
    E_SIGNATURE_ROLE_UNAUTHORIZED,
    UpdateError,
)
from .signing import payload_digest, verify as verify_signature

ROLE_NAMES = ("root", "snapshot", "target")
DOC_TYPES = ("root", "snapshot", "target")
ZERO_DIGEST = "0" * 64
HEX64 = 64


# --------------------------------------------------------------------------
# small validation helpers
# --------------------------------------------------------------------------
def require_dict(value, field_name: str) -> dict:
    if not isinstance(value, dict):
        raise UpdateError(E_INPUT_INVALID, f"{field_name} must be an object", {"field": field_name})
    return value


def require_int(value, field_name: str, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise UpdateError(E_INPUT_INVALID, f"{field_name} must be an integer", {"field": field_name})
    if minimum is not None and value < minimum:
        raise UpdateError(E_INPUT_INVALID, f"{field_name} must be >= {minimum}", {"field": field_name})
    return value


def require_str(value, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise UpdateError(E_INPUT_INVALID, f"{field_name} must be a non-empty string", {"field": field_name})
    return value


def require_doc_headers(doc: dict, doc_type: str, tenant: str) -> None:
    if doc.get("doc_type") != doc_type:
        raise UpdateError(
            E_INPUT_INVALID, "document type mismatch", {"expected": doc_type, "actual": doc.get("doc_type")}
        )
    if doc.get("tenant") != tenant:
        raise UpdateError(
            E_INPUT_INVALID, "document belongs to another tenant", {"expected": tenant, "actual": doc.get("tenant")}
        )


# --------------------------------------------------------------------------
# role policy
# --------------------------------------------------------------------------
def is_wildcard(values) -> bool:
    return isinstance(values, list) and values == ["*"]


def check_policy_shape(role_name: str, policy) -> None:
    policy = require_dict(policy, f"roles.{role_name}")
    require_int(policy.get("threshold"), f"roles.{role_name}.threshold", 1)
    holders = require_dict(policy.get("holders"), f"roles.{role_name}.holders")
    if not holders:
        raise UpdateError(E_ROOT_DOC_INVALID, f"role {role_name} has no holders")
    key_seen: set = set()
    for holder, keys in holders.items():
        require_str(holder, f"roles.{role_name}.holders key")
        if not isinstance(keys, list) or not keys:
            raise UpdateError(E_ROOT_DOC_INVALID, f"holder {holder} has no keys", {"role": role_name})
        for key in keys:
            require_str(key, f"roles.{role_name}.holders[{holder}]")
            if key in key_seen:
                raise UpdateError(
                    E_ROOT_DOC_INVALID, f"key {key} is listed twice in role {role_name}", {"role": role_name}
                )
            key_seen.add(key)
    if policy["threshold"] > len(holders):
        raise UpdateError(
            E_ROOT_DOC_INVALID,
            f"role {role_name} threshold {policy['threshold']} exceeds its {len(holders)} holders",
            {"role": role_name},
        )
    revoked = policy.get("revoked", [])
    if not isinstance(revoked, list):
        raise UpdateError(E_ROOT_DOC_INVALID, f"roles.{role_name}.revoked must be a list", {"role": role_name})
    revoked_keys: set = set()
    for entry in revoked:
        entry = require_dict(entry, f"roles.{role_name}.revoked[]")
        key_id = require_str(entry.get("key_id"), f"roles.{role_name}.revoked[].key_id")
        gen = require_int(entry.get("gen"), f"roles.{role_name}.revoked[].gen", 1)
        if (key_id, gen) in revoked_keys:
            raise UpdateError(
                E_ROOT_DOC_INVALID, "a revoked generation is listed twice", {"key_id": key_id, "gen": gen}
            )
        revoked_keys.add((key_id, gen))
    tags = policy.get("tags")
    if not isinstance(tags, list) or not tags:
        raise UpdateError(E_ROOT_DOC_INVALID, f"roles.{role_name}.tags must be a non-empty list", {"role": role_name})
    paths = policy.get("paths")
    if not isinstance(paths, list) or not paths:
        raise UpdateError(E_ROOT_DOC_INVALID, f"roles.{role_name}.paths must be a non-empty list", {"role": role_name})
    if not is_wildcard(paths):
        for prefix in paths:
            try:
                normalize_repo_path(prefix)
            except UpdateError:
                raise UpdateError(
                    E_ROOT_DOC_INVALID, f"invalid path prefix {prefix!r} in role {role_name}", {"role": role_name}
                ) from None


def check_role_exclusivity(root: dict) -> None:
    """No holder and no key may serve two roles of the same root."""
    holder_owner: dict = {}
    key_owner_map: dict = {}
    for role_name in ROLE_NAMES:
        policy = root["roles"][role_name]
        for holder, keys in policy["holders"].items():
            if holder in holder_owner:
                raise UpdateError(
                    E_ROLE_EXCLUSIVITY,
                    f"holder {holder} appears in both {holder_owner[holder]} and {role_name}",
                    {"holder": holder, "roles": [holder_owner[holder], role_name]},
                )
            holder_owner[holder] = role_name
            for key in keys:
                if key in key_owner_map:
                    raise UpdateError(
                        E_ROLE_EXCLUSIVITY,
                        f"key {key} appears in both {key_owner_map[key]} and {role_name}",
                        {"key_id": key, "roles": [key_owner_map[key], role_name]},
                    )
                key_owner_map[key] = role_name


def check_keyring(root: dict) -> None:
    keyring = require_dict(root.get("keyring"), "keyring")
    role_keys = {
        key
        for role_name in ROLE_NAMES
        for keys in root["roles"][role_name]["holders"].values()
        for key in keys
    }
    if set(keyring) != role_keys:
        raise UpdateError(
            E_ROOT_DOC_INVALID,
            "keyring must contain exactly the keys referenced by the three roles",
            {"missing": sorted(role_keys - set(keyring)), "extra": sorted(set(keyring) - role_keys)},
        )
    for key, secret in keyring.items():
        if not isinstance(secret, str) or len(secret) != HEX64:
            raise UpdateError(
                E_ROOT_DOC_INVALID, f"keyring entry {key} is not 64 hex characters", {"key_id": key}
            )


def parse_root(doc: dict, tenant: str) -> dict:
    require_doc_headers(doc, "root", tenant)
    version = require_int(doc.get("version"), "version", 1)
    previous = require_int(doc.get("previous_version"), "previous_version", 0)
    if version == 1:
        if previous != 0:
            raise UpdateError(E_ROOT_DOC_INVALID, "root version 1 must have previous_version 0")
        if doc.get("previous_digest") != ZERO_DIGEST:
            raise UpdateError(E_ROOT_DOC_INVALID, "root version 1 must have the zero previous_digest")
    else:
        if previous != version - 1:
            raise UpdateError(
                E_ROOT_DOC_INVALID,
                "previous_version must be version - 1",
                {"version": version, "previous_version": previous},
            )
        if not is_sha256_hex(doc.get("previous_digest")):
            raise UpdateError(E_ROOT_DOC_INVALID, "previous_digest must be a sha256 hex digest")
    require_int(doc.get("issued_at"), "issued_at", 0)
    require_int(doc.get("expires_at"), "expires_at", 0)
    if doc["expires_at"] <= doc["issued_at"]:
        raise UpdateError(E_ROOT_DOC_INVALID, "expires_at must be after issued_at")
    roles = require_dict(doc.get("roles"), "roles")
    if set(roles) != set(ROLE_NAMES):
        raise UpdateError(
            E_ROOT_DOC_INVALID,
            "root must define exactly root, snapshot and target roles",
            {"roles": sorted(roles)},
        )
    for role_name in ROLE_NAMES:
        check_policy_shape(role_name, roles[role_name])
    if roles["root"]["tags"] != ["*"] or roles["root"]["paths"] != ["*"]:
        raise UpdateError(E_ROOT_DOC_INVALID, "the root role must be authorized for all tags and paths")
    check_role_exclusivity(doc)
    check_keyring(doc)
    if not isinstance(doc.get("signatures"), list):
        raise UpdateError(E_ROOT_DOC_INVALID, "root document must carry a signatures list")
    return doc


def role_authorized(policy: dict, repo_tag: str, paths: list) -> tuple:
    """Check tag + every path; return ``(ok, offending_path, offending_tag)``."""
    if not is_wildcard(policy["tags"]) and repo_tag not in policy["tags"]:
        return False, None, repo_tag
    if is_wildcard(policy["paths"]):
        return True, None, None
    prefixes = [tuple(path_segments(p)) for p in policy["paths"]]
    for path in paths:
        segs = path_segments(path)
        if not any(len(prefix) <= len(segs) and segs[: len(prefix)] == prefix for prefix in prefixes):
            return False, path, None
    return True, None, None


# --------------------------------------------------------------------------
# signature evaluation
# --------------------------------------------------------------------------
@dataclass
class RoleSignatureReport:
    """Result of evaluating one role's signatures on one document."""

    role: str
    threshold: int
    holders: list = field(default_factory=list)
    keys_used: list = field(default_factory=list)
    accepted: bool = False
    revoked: list = field(default_factory=list)
    duplicates_skipped: int = 0
    unknown_keys: list = field(default_factory=list)
    role_violations: list = field(default_factory=list)
    records: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "role": self.role,
            "threshold": self.threshold,
            "holders": list(self.holders),
            "keys_used": list(self.keys_used),
            "accepted": self.accepted,
            "revoked_skipped": list(self.revoked),
            "duplicates_skipped": self.duplicates_skipped,
        }


def key_owner(root: dict, key_id: str) -> tuple | None:
    for role_name in ROLE_NAMES:
        for holder, keys in root["roles"][role_name]["holders"].items():
            if key_id in keys:
                return role_name, holder
    return None


def _revoked_set(policy: dict) -> set:
    return {(entry["key_id"], entry["gen"]) for entry in policy.get("revoked", [])}


def _unique_records(doc: dict) -> tuple:
    """Validate record shape and drop exact repeats (same key/gen/nonce)."""
    records = doc.get("signatures", [])
    if not isinstance(records, list):
        raise UpdateError(E_SIGNATURE_INVALID, "signatures must be a list")
    deduped: list = []
    seen: set = set()
    duplicates = 0
    for record in records:
        if not isinstance(record, dict):
            raise UpdateError(E_SIGNATURE_INVALID, "signature record must be an object")
        key_id = record.get("key_id")
        gen = record.get("gen")
        nonce = record.get("nonce")
        if not isinstance(key_id, str) or not key_id:
            raise UpdateError(E_SIGNATURE_INVALID, "signature record lacks key_id")
        if not isinstance(gen, int) or isinstance(gen, bool) or gen < 1:
            raise UpdateError(E_SIGNATURE_INVALID, "signature gen must be a positive integer", {"key_id": key_id})
        if not isinstance(nonce, str) or not nonce:
            raise UpdateError(E_SIGNATURE_INVALID, "signature record lacks a nonce", {"key_id": key_id})
        marker = (key_id, gen, nonce)
        if marker in seen:
            duplicates += 1
            continue
        seen.add(marker)
        deduped.append(record)
    return deduped, duplicates


def role_signature_report(doc: dict, root: dict, role_name: str) -> RoleSignatureReport:
    """Evaluate and verify every signature that belongs to ``role_name``."""
    policy = root["roles"][role_name]
    keyring = root["keyring"]
    revoked = _revoked_set(policy)
    records, duplicates = _unique_records(doc)
    report = RoleSignatureReport(role=role_name, threshold=policy["threshold"], duplicates_skipped=duplicates)
    holders: list = []

    for record in records:
        key_id = record["key_id"]
        owner = key_owner(root, key_id)
        if owner is None:
            report.unknown_keys.append(key_id)
            continue
        if owner[0] != role_name:
            report.role_violations.append(key_id)
            continue
        if (key_id, record["gen"]) in revoked:
            report.revoked.append(f"{key_id}#{record['gen']}")
            continue
        verify_signature(doc, record, keyring[key_id])
        record["_holder"] = owner[1]
        report.records.append(record)
        if owner[1] not in holders:
            holders.append(owner[1])
            report.keys_used.append(key_id)
    report.holders = holders
    report.accepted = len(holders) >= policy["threshold"]
    return report


def require_threshold(doc: dict, root: dict, role_name: str, error_code: str) -> RoleSignatureReport:
    report = role_signature_report(doc, root, role_name)
    if report.unknown_keys:
        raise UpdateError(
            E_SIGNATURE_INVALID,
            "a signature uses a key the confirmed root does not know",
            {"key_ids": sorted(set(report.unknown_keys)), "role": role_name},
        )
    if report.role_violations:
        raise UpdateError(
            E_SIGNATURE_ROLE_UNAUTHORIZED,
            "a key from another role signed this document",
            {"key_ids": sorted(set(report.role_violations)), "required_role": role_name},
        )
    if not report.accepted:
        raise UpdateError(
            error_code,
            f"{role_name} threshold not met for {doc.get('doc_type')} v{doc.get('version')}: "
            f"{len(report.holders)}/{report.threshold} holders",
            {
                "role": role_name,
                "threshold": report.threshold,
                "holders": report.holders,
                "revoked_skipped": report.revoked,
            },
        )
    return report


# --------------------------------------------------------------------------
# root rotation: two simultaneous quorums with disjoint holders
# --------------------------------------------------------------------------
@dataclass
class RotationReport:
    old: RoleSignatureReport
    new: RoleSignatureReport
    shared_holders: list
    old_candidates: list
    new_candidates: list
    ok: bool
    reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "old": self.old.as_dict(),
            "new": self.new.as_dict(),
            "shared_holders": list(self.shared_holders),
            "old_candidates": list(self.old_candidates),
            "new_candidates": list(self.new_candidates),
        }


def _assign_disjoint(old_only: list, new_only: list, shared: list, k_old: int, k_new: int):
    """Greedy feasible assignment of seats; ``None`` when Hall's condition fails."""
    old_sel = list(old_only[:k_old])
    new_sel = list(new_only[:k_new])
    need_old = k_old - len(old_sel)
    need_new = k_new - len(new_sel)
    if need_old + need_new > len(shared):
        return None
    old_sel.extend(shared[:need_old])
    new_sel.extend(shared[need_old:need_old + need_new])
    if len(set(old_sel)) < k_old or len(set(new_sel)) < k_new or set(old_sel) & set(new_sel):
        return None
    return old_sel, new_sel


def evaluate_rotation(doc: dict, old_root: dict, new_root: dict) -> RotationReport:
    """Simultaneously satisfy the old and new root thresholds with distinct holders."""
    records, duplicates = _unique_records(doc)
    old_policy = old_root["roles"]["root"]
    new_policy = new_root["roles"]["root"]
    old_revoked = _revoked_set(old_policy)
    new_revoked = _revoked_set(new_policy)

    old_report = RoleSignatureReport(role="root", threshold=old_policy["threshold"], duplicates_skipped=duplicates)
    new_report = RoleSignatureReport(role="root", threshold=new_policy["threshold"], duplicates_skipped=duplicates)

    old_holders: list = []
    new_holders: list = []
    unknown: list = []
    violations: list = []

    for record in records:
        key_id = record["key_id"]
        gen = record["gen"]
        owner_old = key_owner(old_root, key_id) if key_id in old_root["keyring"] else None
        owner_new = key_owner(new_root, key_id) if key_id in new_root["keyring"] else None
        if owner_old is None and owner_new is None:
            unknown.append(key_id)
            continue
        bad_role = False
        if owner_old is not None and owner_old[0] != "root":
            bad_role = True
        if owner_new is not None and owner_new[0] != "root":
            bad_role = True
        if bad_role:
            violations.append(key_id)
            continue

        # Verify against every keyring that holds the key.  A carried-over key
        # id must verify with the same secret on both sides; the updater
        # enforces secret continuity before this point.
        if owner_old is not None:
            verify_signature(doc, record, old_root["keyring"][key_id])
        if owner_new is not None:
            verify_signature(doc, record, new_root["keyring"][key_id])

        if owner_old is not None and (key_id, gen) not in old_revoked:
            record["_old_holder"] = owner_old[1]
            old_report.records.append(record)
            if owner_old[1] not in old_holders:
                old_holders.append(owner_old[1])
                old_report.keys_used.append(key_id)
        elif owner_old is not None:
            old_report.revoked.append(f"{key_id}#{gen}")

        if owner_new is not None and (key_id, gen) not in new_revoked:
            record["_new_holder"] = owner_new[1]
            new_report.records.append(record)
            if owner_new[1] not in new_holders:
                new_holders.append(owner_new[1])
                new_report.keys_used.append(key_id)
        elif owner_new is not None:
            new_report.revoked.append(f"{key_id}#{gen}")

    old_report.holders = sorted(old_holders)
    new_report.holders = sorted(new_holders)
    old_report.unknown_keys = sorted(set(unknown))
    new_report.role_violations = sorted(set(violations))

    shared = sorted(set(old_holders) & set(new_holders))
    report = RotationReport(
        old=old_report,
        new=new_report,
        shared_holders=shared,
        old_candidates=sorted(old_holders),
        new_candidates=sorted(new_holders),
        ok=False,
    )
    if unknown:
        report.reason = "unknown_keys"
        return report
    if violations:
        report.reason = "role_violation"
        return report

    k_old = old_policy["threshold"]
    k_new = new_policy["threshold"]
    if len(old_holders) < k_old:
        report.reason = "old_threshold"
        return report
    if len(new_holders) < k_new:
        report.reason = "new_threshold"
        return report

    old_only = sorted(set(old_holders) - set(shared))
    new_only = sorted(set(new_holders) - set(shared))
    assignment = _assign_disjoint(old_only, new_only, shared, k_old, k_new)
    if assignment is None:
        report.reason = "holder_overlap"
        return report

    old_selected, new_selected = assignment
    old_report.holders = sorted(old_selected)
    new_report.holders = sorted(new_selected)
    old_report.accepted = True
    new_report.accepted = True
    report.ok = True
    return report


# --------------------------------------------------------------------------
# snapshot / target shapes
# --------------------------------------------------------------------------
def parse_snapshot(doc: dict, tenant: str) -> dict:
    require_doc_headers(doc, "snapshot", tenant)
    version = require_int(doc.get("version"), "version", 1)
    previous = require_int(doc.get("previous_version"), "previous_version", 0)
    if version == 1:
        if doc.get("previous_digest") != ZERO_DIGEST:
            raise UpdateError(E_INPUT_INVALID, "snapshot version 1 must have the zero previous_digest")
    elif previous != version - 1 or not is_sha256_hex(doc.get("previous_digest")):
        raise UpdateError(E_INPUT_INVALID, "snapshot does not link to its predecessor", {"version": version})
    require_int(doc.get("issued_at"), "issued_at", 0)
    require_int(doc.get("expires_at"), "expires_at", 0)
    if doc["expires_at"] <= doc["issued_at"]:
        raise UpdateError(E_INPUT_INVALID, "snapshot expires_at must be after issued_at")
    require_str(doc.get("channel"), "channel")
    require_str(doc.get("repo_tag"), "repo_tag")
    require_int(doc.get("root_version"), "root_version", 1)
    entries = doc.get("entries")
    if not isinstance(entries, list):
        raise UpdateError(E_INPUT_INVALID, "snapshot.entries must be a list")
    seen_targets: set = set()
    for entry in entries:
        require_dict(entry, "entries[]")
        target_id = require_str(entry.get("target_id"), "entries[].target_id")
        if target_id in seen_targets:
            raise UpdateError(E_INPUT_INVALID, f"snapshot lists target {target_id} twice", {"target_id": target_id})
        seen_targets.add(target_id)
        require_int(entry.get("version"), "entries[].version", 1)
        require_str(entry.get("purpose"), "entries[].purpose")
        require_str(entry.get("repo_tag"), "entries[].repo_tag")
        try:
            normalize_repo_path(entry.get("path"))
        except UpdateError:
            raise UpdateError(E_PATH_ESCAPE, "snapshot entry path is not canonical", {"target_id": target_id}) from None
        for field_name in ("manifest_digest", "file_digest"):
            if not is_sha256_hex(entry.get(field_name)):
                raise UpdateError(
                    E_INPUT_INVALID,
                    f"entries[{target_id}].{field_name} must be a sha256 hex digest",
                    {"target_id": target_id},
                )
    if not isinstance(doc.get("signatures"), list):
        raise UpdateError(E_INPUT_INVALID, "snapshot must carry a signatures list")
    return doc


def parse_target(doc: dict, tenant: str) -> dict:
    require_doc_headers(doc, "target", tenant)
    require_str(doc.get("target_id"), "target_id")
    version = require_int(doc.get("version"), "version", 1)
    previous = require_int(doc.get("previous_version"), "previous_version", 0)
    if version == 1:
        if doc.get("previous_digest") != ZERO_DIGEST:
            raise UpdateError(E_INPUT_INVALID, "target version 1 must have the zero previous_digest")
    elif previous != version - 1 or not is_sha256_hex(doc.get("previous_digest")):
        raise UpdateError(
            E_INPUT_INVALID, "target does not link to its predecessor", {"target_id": doc.get("target_id")}
        )
    require_int(doc.get("issued_at"), "issued_at", 0)
    require_int(doc.get("expires_at"), "expires_at", 0)
    if doc["expires_at"] <= doc["issued_at"]:
        raise UpdateError(E_INPUT_INVALID, "target expires_at must be after issued_at")
    require_int(doc.get("root_version"), "root_version", 1)
    require_int(doc.get("snapshot_version"), "snapshot_version", 1)
    require_str(doc.get("channel"), "channel")
    require_str(doc.get("purpose"), "purpose")
    require_str(doc.get("repo_tag"), "repo_tag")
    normalize_repo_path(doc.get("path"))
    file_info = require_dict(doc.get("file"), "file")
    if not is_sha256_hex(file_info.get("digest")):
        raise UpdateError(E_INPUT_INVALID, "file.digest must be a sha256 hex digest")
    require_int(file_info.get("size"), "file.size", 0)
    if not isinstance(doc.get("signatures"), list):
        raise UpdateError(E_INPUT_INVALID, "target must carry a signatures list")
    return doc


# --------------------------------------------------------------------------
# identity helpers
# --------------------------------------------------------------------------
def doc_key(doc: dict) -> tuple:
    if doc.get("doc_type") == "root":
        return ("root", doc.get("version"))
    if doc.get("doc_type") == "snapshot":
        return ("snapshot", doc.get("channel"), doc.get("version"))
    return ("target", doc.get("target_id"), doc.get("version"))


def doc_key_text(doc: dict) -> str:
    return "|".join(str(part) for part in doc_key(doc))


def doc_digest(doc: dict) -> str:
    return payload_digest(doc)


def digest_of(value) -> str:
    return digest_json(value)


__all__ = [
    "ROLE_NAMES",
    "ZERO_DIGEST",
    "RoleSignatureReport",
    "RotationReport",
    "doc_digest",
    "doc_key",
    "doc_key_text",
    "evaluate_rotation",
    "key_owner",
    "parse_root",
    "parse_snapshot",
    "parse_target",
    "require_threshold",
    "role_authorized",
    "role_signature_report",
]
