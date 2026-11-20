"""Update pipeline: prepare outside a transaction, then publish inside one.

``Updater.prepare`` runs the *entire* trust algebra against a snapshot of
client state.  ``Updater.publish`` then re-opens that state under
``BEGIN IMMEDIATE`` and re-derives every fact it is about to commit:

* the confirmed root version and digest,
* every affected channel watermark,
* every affected target floor,
* the trusted-time watermark,
* the digest of every input document, payload file and the package index as
  they exist on disk *right now*,
* that no signature record it is about to consume has already been consumed.

Only if all of that still matches does it write.  A concurrent writer
therefore either loses with ``E_CONCURRENCY_CONFLICT`` or wins atomically -
there is no interleaving that can publish a stale pointer.

The package is all-or-nothing: every root step, snapshot, target and payload
file is verified before the first row is written, and the write is a single
transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import syncpoint
from .canonical import digest_json
from .docs import (
    ZERO_DIGEST,
    RoleSignatureReport,
    doc_digest,
    evaluate_rotation,
    parse_root,
    parse_snapshot,
    parse_target,
    require_threshold,
    role_authorized,
)
from .errors import (
    E_CONCURRENCY_CONFLICT,
    E_FILE_DIGEST_MISMATCH,
    E_FILE_MISSING,
    E_INPUT_INVALID,
    E_MANIFEST_CONFLICT,
    E_MANIFEST_VERSION_ROLLBACK,
    E_REQUEST_REPLAY_CONFLICT,
    E_ROOT_ANCHOR_MISMATCH,
    E_ROOT_EXPIRED,
    E_ROOT_HOLDER_OVERLAP,
    E_ROOT_NEW_THRESHOLD,
    E_ROOT_NOT_YET_VALID,
    E_ROOT_OLD_THRESHOLD,
    E_ROOT_ROLLBACK,
    E_ROOT_VERSION_ORDER,
    E_ROOT_VERSION_SKIP,
    E_SIGNATURE_INVALID,
    E_SIGNATURE_REPLAY,
    E_SIGNATURE_ROLE_UNAUTHORIZED,
    E_SNAPSHOT_CONFLICT,
    E_SNAPSHOT_EXPIRED,
    E_SNAPSHOT_NOT_CONFIRMED_ROOT,
    E_SNAPSHOT_NOT_YET_VALID,
    E_SNAPSHOT_THRESHOLD,
    E_SNAPSHOT_UNAUTHORIZED,
    E_SNAPSHOT_VERSION_ORDER,
    E_SNAPSHOT_VERSION_ROLLBACK,
    E_TARGET_CHANNEL,
    E_TARGET_DIGEST_MISMATCH,
    E_TARGET_NOT_CONFIRMED_ROOT,
    E_TARGET_EXPIRED,
    E_TARGET_MIXED_SNAPSHOT,
    E_TARGET_NOT_IN_SNAPSHOT,
    E_TARGET_NOT_YET_VALID,
    E_TARGET_PATH_MISMATCH,
    E_TARGET_PATH_UNAUTHORIZED,
    E_TARGET_PURPOSE,
    E_TARGET_THRESHOLD,
    E_TARGET_UNAUTHORIZED,
    E_TIME_ROLLBACK,
    UpdateError,
)
from .loader import LoadedPackage, PackageReader
from .state import Store


# --------------------------------------------------------------------------
# plan structures
# --------------------------------------------------------------------------
@dataclass
class RootStep:
    old_root: dict
    new_root: dict
    rotation: object

    def table_row(self, index: int, trusted_time: int) -> dict:
        return {
            "step": index,
            "role": "root",
            "from_version": self.old_root["version"],
            "from_digest": doc_digest(self.old_root),
            "to_version": self.new_root["version"],
            "to_digest": doc_digest(self.new_root),
            "trusted_time": trusted_time,
            "old_root_quorum": {
                "threshold": self.rotation.old.threshold,
                "holders": self.rotation.old.holders,
                "keys": self.rotation.old.keys_used,
            },
            "new_root_quorum": {
                "threshold": self.rotation.new.threshold,
                "holders": self.rotation.new.holders,
                "keys": self.rotation.new.keys_used,
            },
            "shared_holders": self.rotation.shared_holders,
            "revoked_skipped": sorted(
                set(self.rotation.old.revoked) | set(self.rotation.new.revoked)
            ),
            "duplicates_skipped": self.rotation.old.duplicates_skipped,
            "accepted": self.rotation.ok,
        }


@dataclass
class SnapshotPlan:
    doc: dict
    digest: str
    previous_digest: str
    report: RoleSignatureReport


@dataclass
class TargetPlan:
    doc: dict
    digest: str
    snapshot_version: int
    snapshot_digest: str
    file_digest: str
    file_size: int
    content: bytes
    report: RoleSignatureReport


@dataclass
class UpdatePlan:
    tenant: str
    request_id: str
    trusted_time: int
    package: LoadedPackage
    package_digest: str
    root_before: dict
    root_after: dict
    root_steps: list = field(default_factory=list)
    snapshots: list = field(default_factory=list)
    targets: list = field(default_factory=list)
    noops: list = field(default_factory=list)
    input_digests: dict = field(default_factory=dict)
    pre: object = None

    def trust_table(self) -> list:
        rows = [step.table_row(index, self.trusted_time) for index, step in enumerate(self.root_steps, start=1)]
        for snap in self.snapshots:
            rows.append(
                {
                    "role": "snapshot",
                    "channel": snap.doc["channel"],
                    "version": snap.doc["version"],
                    "root_version": snap.doc["root_version"],
                    "digest": snap.digest,
                    "threshold": snap.report.threshold,
                    "holders": snap.report.holders,
                    "keys": snap.report.keys_used,
                    "revoked_skipped": snap.report.revoked,
                    "accepted": snap.report.accepted,
                }
            )
        for target in self.targets:
            rows.append(
                {
                    "role": "target",
                    "target_id": target.doc["target_id"],
                    "version": target.doc["version"],
                    "channel": target.doc["channel"],
                    "path": target.doc["path"],
                    "snapshot_version": target.snapshot_version,
                    "snapshot_digest": target.snapshot_digest,
                    "manifest_digest": target.digest,
                    "file_digest": target.file_digest,
                    "threshold": target.report.threshold,
                    "holders": target.report.holders,
                    "keys": target.report.keys_used,
                    "accepted": target.report.accepted,
                }
            )
        return rows


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _within(doc: dict, trusted_time: int, expired_code: str, early_code: str, what: str) -> None:
    """Half-open validity window ``[issued_at, expires_at)``.

    ``trusted_time == expires_at`` is *expired*: the document is valid only up
    to, not including, its expiry instant.
    """
    issued = doc["issued_at"]
    expires = doc["expires_at"]
    if trusted_time >= expires:
        raise UpdateError(
            expired_code,
            f"{what} v{doc.get('version')} expired at {expires} (trusted_time={trusted_time})",
            {"issued_at": issued, "expires_at": expires, "trusted_time": trusted_time},
        )
    if trusted_time < issued:
        raise UpdateError(
            early_code,
            f"{what} v{doc.get('version')} is not valid before {issued} (trusted_time={trusted_time})",
            {"issued_at": issued, "expires_at": expires, "trusted_time": trusted_time},
        )


def _parse_snapshot(doc: dict, tenant: str) -> dict:
    """Parse a snapshot, mapping generic field errors to ``E_SNAPSHOT_INVALID``."""
    try:
        return parse_snapshot(doc, tenant)
    except UpdateError as exc:
        if exc.code == E_INPUT_INVALID:
            raise UpdateError(E_SNAPSHOT_INVALID, exc.message, exc.detail) from None
        raise


def _parse_target(doc: dict, tenant: str) -> dict:
    """Parse a target, mapping generic field errors to ``E_MANIFEST_INVALID``."""
    try:
        return parse_target(doc, tenant)
    except UpdateError as exc:
        if exc.code == E_INPUT_INVALID:
            raise UpdateError(E_MANIFEST_INVALID, exc.message, exc.detail) from None
        raise


def _claim_records(plan: UpdatePlan) -> list:
    """Signature records that participate in an accepted quorum of this plan.

    A rotation record is evaluated once against the old root and once against
    the new root, so the same physical record can appear twice.  Claims are
    deduplicated by ``(key_id, gen, nonce)`` before they reach the store.
    """
    seen: set = set()
    records: list = []

    def add(items) -> None:
        for record in items:
            marker = (record["key_id"], record["gen"], record["nonce"])
            if marker in seen:
                continue
            seen.add(marker)
            records.append(record)

    for step in plan.root_steps:
        add(step.rotation.old.records)
        add(step.rotation.new.records)
    for snap in plan.snapshots:
        add(snap.report.records)
    for target in plan.targets:
        add(target.report.records)
    return records


# --------------------------------------------------------------------------
# updater
# --------------------------------------------------------------------------
class Updater:
    def __init__(self, store: Store) -> None:
        self.store = store

    # -- prepare -----------------------------------------------------------
    def prepare(self, tenant: str, package_dir: str, request_id: str, trusted_time: int) -> UpdatePlan:
        if not isinstance(request_id, str) or not request_id:
            raise UpdateError(E_INPUT_INVALID, "request_id must be a non-empty string")
        if not isinstance(trusted_time, int) or isinstance(trusted_time, bool) or trusted_time < 0:
            raise UpdateError(E_INPUT_INVALID, "trusted_time must be a non-negative integer")

        meta = self.store.tenant_meta(tenant)
        if trusted_time < meta["trusted_time"]:
            raise UpdateError(
                E_TIME_ROLLBACK,
                "trusted time may not move backwards",
                {"stored": meta["trusted_time"], "requested": trusted_time},
            )

        package = PackageReader(package_dir).load()
        if package.tenant != tenant:
            raise UpdateError(
                E_INPUT_INVALID,
                "package tenant does not match the request tenant",
                {"package_tenant": package.tenant, "request_tenant": tenant},
            )
        package_digest = self._package_digest(package)

        # Take ONE consistent pre-state snapshot and verify entirely against
        # it.  Reading the root and then the watermarks in two separate reads
        # would let a concurrent writer slip in between, so the package could
        # be verified against a root that is no longer the confirmed one while
        # the recorded pre-state already reflects the newer root - and the
        # in-transaction recheck would then pass on stale facts.
        pre = self.store.pre_state(tenant)
        root_before = pre.root_doc
        root_after, root_steps = self._verify_root_chain(tenant, root_before, package, trusted_time)

        snapshot_plans, noop_snapshots = self._verify_snapshots(tenant, root_after, package, trusted_time, pre)
        target_plans, noop_targets = self._verify_targets(
            tenant, root_after, package, snapshot_plans, trusted_time, pre
        )

        plan = UpdatePlan(
            tenant=tenant,
            request_id=request_id,
            trusted_time=trusted_time,
            package=package,
            package_digest=package_digest,
            root_before=root_before,
            root_after=root_after,
            root_steps=root_steps,
            snapshots=snapshot_plans,
            targets=target_plans,
            noops=noop_snapshots + noop_targets,
            input_digests=package.all_input_digests(),
        )
        plan.pre = pre
        return plan

    # -- publish -----------------------------------------------------------
    def publish(self, plan: UpdatePlan) -> dict:
        tenant = plan.tenant
        outcome = self._publish_locked(plan)
        syncpoint.hit("after_commit_before_return")
        return outcome

    def _publish_locked(self, plan: UpdatePlan) -> dict:
        tenant = plan.tenant
        with self.store.write_txn() as conn:
            existing = self.store.receipt(tenant, plan.request_id, conn)
            if existing is not None:
                if existing["package_digest"] != plan.package_digest:
                    raise UpdateError(
                        E_REQUEST_REPLAY_CONFLICT,
                        "request_id was already used for a different package",
                        {"request_id": plan.request_id},
                    )
                return {"status": "replayed", "receipt": existing}

            self._revalidate_in_transaction(plan, conn)

            for step in plan.root_steps:
                self.store.put_root(conn, tenant, step.new_root, doc_digest(step.new_root), plan.trusted_time)
            for snap in plan.snapshots:
                self.store.put_snapshot(conn, tenant, snap.doc, snap.digest, plan.trusted_time)
            for target in plan.targets:
                self.store.put_blob(conn, tenant, target.file_digest, target.content)
                self.store.put_target(conn, tenant, target.doc, target.digest, plan.trusted_time)
            # Pointers only after the snapshot/document rows exist, so the
            # database triggers can prove every pointer target is present.
            for snap in plan.snapshots:
                self.store.put_channel_pointer(
                    conn, tenant, snap.doc["channel"], snap.doc["version"], snap.digest
                )
            self.store.put_tenant_meta(
                conn, tenant, plan.trusted_time, plan.root_after["version"], doc_digest(plan.root_after)
            )
            self.store.claim_signatures(conn, tenant, _claim_records(plan))

            receipt = self._build_receipt(plan)
            self.store.put_receipt(conn, tenant, plan.request_id, plan.package_digest, receipt, plan.trusted_time)

            # Crash fence: root rows written, watermark moved, receipt
            # written - but the transaction has not committed yet.
            syncpoint.hit("before_publish_commit")
            return {"status": "committed", "receipt": receipt}

    # -- package digest ----------------------------------------------------
    @staticmethod
    def _package_digest(package: LoadedPackage) -> str:
        return digest_json(package.all_input_digests())

    # -- root chain --------------------------------------------------------
    def _verify_root_chain(self, tenant: str, root_before: dict, package: LoadedPackage, trusted_time: int):
        # Whatever root we end up trusting, it must be valid at this instant:
        # either the confirmed root is still current, or the rotation we are
        # about to install carries us to a root that is.  Without this check an
        # expired anchor would keep authorizing new snapshots forever.
        _within(root_before, trusted_time, E_ROOT_EXPIRED, E_ROOT_NOT_YET_VALID, "root")
        current = root_before
        current_digest = doc_digest(current)
        steps: list = []
        roots = package.roots()
        for version in sorted(roots):
            doc = roots[version]
            parse_root(doc, tenant)
            if version < current["version"]:
                raise UpdateError(
                    E_ROOT_ROLLBACK,
                    "package attempts to lower the confirmed root version",
                    {"confirmed": current["version"], "offered": version},
                )
            if version == current["version"]:
                if doc_digest(doc) != current_digest:
                    raise UpdateError(
                        E_ROOT_ANCHOR_MISMATCH,
                        "package offers different bytes for the confirmed root version",
                        {"version": version, "confirmed_digest": current_digest, "offered_digest": doc_digest(doc)},
                    )
                continue
            if version != current["version"] + 1:
                raise UpdateError(
                    E_ROOT_VERSION_SKIP,
                    "root versions must advance one step at a time",
                    {"from": current["version"], "to": version},
                )
            if doc.get("previous_digest") != current_digest:
                raise UpdateError(
                    E_ROOT_VERSION_ORDER,
                    "new root does not link to the confirmed root digest",
                    {"expected": current_digest, "actual": doc.get("previous_digest")},
                )
            _within(doc, trusted_time, E_ROOT_EXPIRED, E_ROOT_NOT_YET_VALID, "root")
            self._check_key_continuity(current, doc)
            rotation = evaluate_rotation(doc, current, doc)
            self._raise_rotation_errors(rotation, current, doc)
            steps.append(RootStep(old_root=current, new_root=doc, rotation=rotation))
            current = doc
            current_digest = doc_digest(doc)
        return current, steps

    @staticmethod
    def _check_key_continuity(old_root: dict, new_root: dict) -> None:
        old_keyring = old_root["keyring"]
        new_keyring = new_root["keyring"]
        for key_id, secret in new_keyring.items():
            if key_id in old_keyring and old_keyring[key_id] != secret:
                raise UpdateError(
                    E_ROOT_HOLDER_OVERLAP,
                    "a carried-over key id changed its key material",
                    {"key_id": key_id},
                )

    @staticmethod
    def _raise_rotation_errors(rotation, old_root: dict, new_root: dict) -> None:
        reason = rotation.reason
        if reason == "unknown_keys":
            raise UpdateError(
                E_SIGNATURE_INVALID,
                "root rotation carries a key unknown to both roots",
                {"key_ids": rotation.old.unknown_keys},
            )
        if reason == "role_violation":
            raise UpdateError(
                E_SIGNATURE_ROLE_UNAUTHORIZED,
                "a non-root-role key signed the new root",
                {"key_ids": rotation.new.role_violations},
            )
        if reason == "old_threshold":
            raise UpdateError(
                E_ROOT_OLD_THRESHOLD,
                "the old root's root role did not reach its threshold on the new root",
                {
                    "threshold": rotation.old.threshold,
                    "holders": rotation.old.holders,
                    "revoked_skipped": rotation.old.revoked,
                },
            )
        if reason == "new_threshold":
            raise UpdateError(
                E_ROOT_NEW_THRESHOLD,
                "the new root's root role did not reach its threshold on itself",
                {
                    "threshold": rotation.new.threshold,
                    "holders": rotation.new.holders,
                    "revoked_skipped": rotation.new.revoked,
                },
            )
        if reason == "holder_overlap":
            raise UpdateError(
                E_ROOT_NEW_THRESHOLD,
                "old and new root quorums cannot be satisfied by disjoint holders",
                {
                    "old_threshold": rotation.old.threshold,
                    "new_threshold": rotation.new.threshold,
                    "old_holders": rotation.old_candidates,
                    "new_holders": rotation.new_candidates,
                    "shared_holders": rotation.shared_holders,
                },
            )
        if not rotation.ok:  # pragma: no cover - defensive
            raise UpdateError(E_ROOT_NEW_THRESHOLD, "root rotation did not verify")

    # -- snapshots ---------------------------------------------------------
    def _verify_snapshots(self, tenant: str, root: dict, package: LoadedPackage, trusted_time: int, pre):
        channel_versions = dict(pre.channel_versions)
        plans: list = []
        noops: list = []

        by_channel: dict = {}
        for doc in package.snapshots():
            by_channel.setdefault(doc["channel"], {})[doc["version"]] = doc

        for channel in sorted(by_channel):
            floor = channel_versions.get(channel, 0)
            prev_digest = self.store.snapshot_digest(tenant, channel) or ZERO_DIGEST
            for version in sorted(by_channel[channel]):
                doc = by_channel[channel][version]
                _parse_snapshot(doc, tenant)
                if version < floor:
                    raise UpdateError(
                        E_SNAPSHOT_VERSION_ROLLBACK,
                        "snapshot version is below the channel watermark",
                        {"channel": channel, "floor": floor, "offered": version},
                    )
                if version == floor:
                    # Re-offering an already-published version is a no-op only
                    # if it is byte-identical.  It must still carry a quorum
                    # and still be under the confirmed root, or an attacker
                    # could smuggle in arbitrary rows with the same version.
                    stored_digest = self.store.snapshot_digest(tenant, channel)
                    if stored_digest != doc_digest(doc):
                        raise UpdateError(
                            E_SNAPSHOT_CONFLICT,
                            "same channel version re-published with different content",
                            {"channel": channel, "version": version},
                        )
                    if doc["root_version"] != root["version"]:
                        raise UpdateError(
                            E_SNAPSHOT_NOT_CONFIRMED_ROOT,
                            "snapshot is not issued under the confirmed root",
                            {"snapshot_root": doc["root_version"], "confirmed_root": root["version"]},
                        )
                    require_threshold(doc, root, "snapshot", E_SNAPSHOT_THRESHOLD)
                    noops.append({"kind": "snapshot", "channel": channel, "version": version})
                    continue
                if version != floor + 1:
                    raise UpdateError(
                        E_SNAPSHOT_VERSION_ROLLBACK,
                        "snapshot versions must advance one step at a time",
                        {"channel": channel, "from": floor, "to": version},
                    )
                if doc.get("previous_digest") != prev_digest:
                    raise UpdateError(
                        E_SNAPSHOT_VERSION_ORDER,
                        "snapshot does not chain onto the previous channel version",
                        {"channel": channel, "version": version, "expected_previous": prev_digest,
                         "actual_previous": doc.get("previous_digest")},
                    )
                if doc["root_version"] != root["version"]:
                    raise UpdateError(
                        E_SNAPSHOT_NOT_CONFIRMED_ROOT,
                        "snapshot is not issued under the confirmed root",
                        {"snapshot_root": doc["root_version"], "confirmed_root": root["version"]},
                    )
                _within(doc, trusted_time, E_SNAPSHOT_EXPIRED, E_SNAPSHOT_NOT_YET_VALID, "snapshot")
                report = require_threshold(doc, root, "snapshot", E_SNAPSHOT_THRESHOLD)
                ok, offending_path, offending_tag = role_authorized(
                    root["roles"]["snapshot"], doc["repo_tag"], [entry["path"] for entry in doc["entries"]]
                )
                if not ok:
                    raise UpdateError(
                        E_SNAPSHOT_UNAUTHORIZED,
                        "snapshot role is not authorized for this tag or path",
                        {"channel": channel, "version": version, "offending_path": offending_path,
                         "offending_tag": offending_tag},
                    )
                digest = doc_digest(doc)
                plans.append(
                    SnapshotPlan(doc=doc, digest=digest, previous_digest=prev_digest, report=report)
                )
                floor = version
                prev_digest = digest
        return plans, noops

    # -- targets -----------------------------------------------------------
    def _verify_targets(self, tenant: str, root: dict, package: LoadedPackage, snapshot_plans, trusted_time: int, pre):
        planned = {(s.doc["channel"], s.doc["version"]): s for s in snapshot_plans}
        floors = dict(pre.target_floors)
        plans: list = []
        noops: list = []

        by_target: dict = {}
        for doc in package.targets():
            by_target.setdefault(doc["target_id"], {})[doc["version"]] = doc

        for target_id in sorted(by_target):
            floor = floors.get(target_id, 0)
            for version in sorted(by_target[target_id]):
                doc = by_target[target_id][version]
                _parse_target(doc, tenant)
                if version < floor:
                    raise UpdateError(
                        E_MANIFEST_VERSION_ROLLBACK,
                        "target version is below the tenant watermark",
                        {"target_id": target_id, "floor": floor, "offered": version},
                    )
                if version == floor:
                    # Republishing the current version is a no-op only when the
                    # document is truly the confirmed one.  Compare the full
                    # payload digest - not just the file digest - so that a
                    # different purpose, path or signature cannot piggyback on
                    # an existing version number.
                    stored = self.store.target_doc_digest(tenant, target_id, version)
                    if stored != doc_digest(doc):
                        raise UpdateError(
                            E_MANIFEST_CONFLICT,
                            "same target version re-published with different content",
                            {"target_id": target_id, "version": version},
                        )
                    noops.append({"kind": "target", "target_id": target_id, "version": version})
                    continue
                if version != floor + 1:
                    raise UpdateError(
                        E_MANIFEST_VERSION_ROLLBACK,
                        "target versions must advance one step at a time",
                        {"target_id": target_id, "from": floor, "to": version},
                    )

                if doc["root_version"] != root["version"]:
                    raise UpdateError(
                        E_TARGET_NOT_CONFIRMED_ROOT,
                        "target claims to be issued under a different root",
                        {"target_id": target_id, "target_root": doc["root_version"],
                         "confirmed_root": root["version"]},
                    )

                snapshot = self._resolve_snapshot(tenant, doc, planned)
                if doc["channel"] != snapshot["channel"]:
                    raise UpdateError(
                        E_TARGET_CHANNEL,
                        "target channel differs from the snapshot channel",
                        {"target_id": target_id, "target_channel": doc["channel"],
                         "snapshot_channel": snapshot["channel"]},
                    )
                if snapshot["root_version"] != root["version"]:
                    raise UpdateError(
                        E_SNAPSHOT_NOT_CONFIRMED_ROOT,
                        "target is covered by a snapshot from a different root",
                        {"target_id": target_id},
                    )
                entry = self._entry_for_target(snapshot, doc)
                self._check_entry(entry, doc, snapshot, target_id)
                self._check_previous_target(tenant, target_id, doc, floor)

                _within(doc, trusted_time, E_TARGET_EXPIRED, E_TARGET_NOT_YET_VALID, "target")
                report = require_threshold(doc, root, "target", E_TARGET_THRESHOLD)
                self._check_target_authorization(root, doc)

                if doc["path"] not in package.files:
                    raise UpdateError(
                        E_FILE_MISSING,
                        "package does not carry the payload file named by the target",
                        {"target_id": target_id, "path": doc["path"]},
                    )
                file_entry = package.files[doc["path"]]
                if file_entry.digest != doc["file"]["digest"]:
                    raise UpdateError(
                        E_FILE_DIGEST_MISMATCH,
                        "payload file digest does not match the signed manifest",
                        {"target_id": target_id, "path": doc["path"],
                         "expected": doc["file"]["digest"], "actual": file_entry.digest},
                    )
                if file_entry.size != doc["file"]["size"]:
                    raise UpdateError(
                        E_FILE_DIGEST_MISMATCH,
                        "payload size does not match the signed manifest",
                        {"target_id": target_id, "expected": doc["file"]["size"], "actual": file_entry.size},
                    )
                plans.append(
                    TargetPlan(
                        doc=doc,
                        digest=doc_digest(doc),
                        snapshot_version=snapshot["version"],
                        snapshot_digest=doc_digest(snapshot),
                        file_digest=file_entry.digest,
                        file_size=file_entry.size,
                        content=file_entry.content,
                        report=report,
                    )
                )
                floor = version
        return plans, noops

    def _resolve_snapshot(self, tenant: str, doc: dict, planned: dict) -> dict:
        key = (doc["channel"], doc["snapshot_version"])
        if key in planned:
            return planned[key].doc
        stored_version = self.store.channel_versions(tenant).get(doc["channel"], 0)
        if doc["snapshot_version"] != stored_version:
            raise UpdateError(
                E_TARGET_MIXED_SNAPSHOT,
                "target references a snapshot version that is neither published here nor confirmed",
                {"target_id": doc["target_id"], "snapshot_version": doc["snapshot_version"],
                 "confirmed": stored_version},
            )
        snapshot = self.store.snapshot_doc(tenant, doc["channel"], stored_version)
        if snapshot is None:
            raise UpdateError(
                E_TARGET_MIXED_SNAPSHOT,
                "target references a confirmed snapshot whose document is not stored",
                {"target_id": doc["target_id"], "snapshot_version": stored_version},
            )
        return snapshot

    @staticmethod
    def _entry_for_target(snapshot: dict, doc: dict) -> dict:
        for entry in snapshot["entries"]:
            if entry["target_id"] == doc["target_id"]:
                return entry
        raise UpdateError(
            E_TARGET_NOT_IN_SNAPSHOT,
            "target is not listed by the snapshot that must authorize it",
            {"target_id": doc["target_id"], "channel": snapshot["channel"],
             "snapshot_version": snapshot["version"]},
        )

    @staticmethod
    def _check_entry(entry: dict, doc: dict, snapshot: dict, target_id: str) -> None:
        """The snapshot locks the *exact* manifest; anything else is mixed content."""
        if entry["manifest_digest"] != doc_digest(doc):
            raise UpdateError(
                E_TARGET_MIXED_SNAPSHOT,
                "target manifest digest is not the one locked by the snapshot",
                {"target_id": target_id, "snapshot_locked": entry["manifest_digest"],
                 "target_manifest": doc_digest(doc)},
            )
        if entry["version"] != doc["version"]:
            raise UpdateError(
                E_TARGET_MIXED_SNAPSHOT,
                "snapshot pins a different target version",
                {"target_id": target_id, "snapshot": entry["version"], "manifest": doc["version"]},
            )
        if entry["purpose"] != doc["purpose"]:
            raise UpdateError(
                E_TARGET_PURPOSE,
                "target purpose differs from the snapshot entry",
                {"target_id": target_id, "snapshot": entry["purpose"], "manifest": doc["purpose"]},
            )
        if entry["path"] != doc["path"]:
            raise UpdateError(
                E_TARGET_PATH_MISMATCH,
                "target path differs from the snapshot entry",
                {"target_id": target_id, "snapshot": entry["path"], "manifest": doc["path"]},
            )
        if entry["file_digest"] != doc["file"]["digest"]:
            raise UpdateError(
                E_TARGET_DIGEST_MISMATCH,
                "target file digest differs from the snapshot entry",
                {"target_id": target_id, "snapshot": entry["file_digest"],
                 "manifest": doc["file"]["digest"]},
            )
        if entry["repo_tag"] != doc["repo_tag"]:
            raise UpdateError(
                E_TARGET_MIXED_SNAPSHOT,
                "target repository tag differs from the snapshot entry",
                {"target_id": target_id},
            )

    def _check_previous_target(self, tenant: str, target_id: str, doc: dict, floor: int) -> None:
        if floor == 0:
            expected = ZERO_DIGEST
        else:
            expected = self.store.target_doc_digest(tenant, target_id, floor)
            if expected is None:
                raise UpdateError(
                    E_CONCURRENCY_CONFLICT,
                    "target history is missing the previous version",
                    {"target_id": target_id, "floor": floor},
                )
        if doc.get("previous_version") != floor or doc.get("previous_digest") != expected:
            raise UpdateError(
                E_MANIFEST_VERSION_ROLLBACK,
                "target does not chain onto the confirmed previous version",
                {"target_id": target_id, "expected_previous": expected,
                 "actual_previous": doc.get("previous_digest"), "floor": floor},
            )

    @staticmethod
    def _check_target_authorization(root: dict, doc: dict) -> None:
        policy = root["roles"]["target"]
        ok, offending_path, offending_tag = role_authorized(policy, doc["repo_tag"], [doc["path"]])
        if ok:
            return
        if offending_tag is not None:
            raise UpdateError(
                E_TARGET_UNAUTHORIZED,
                "target role is not authorized for the repository tag",
                {"repo_tag": doc["repo_tag"], "target_id": doc["target_id"]},
            )
        raise UpdateError(
            E_TARGET_PATH_UNAUTHORIZED,
            "target role is not authorized for this path segment",
            {"path": offending_path, "target_id": doc["target_id"]},
        )

    # -- in-transaction revalidation ---------------------------------------
    def _revalidate_in_transaction(self, plan: UpdatePlan, conn) -> None:
        tenant = plan.tenant
        meta = self.store.tenant_meta(tenant, conn)
        if meta["root_version"] != plan.pre.root_version or meta["root_digest"] != plan.pre.root_digest:
            raise UpdateError(
                E_CONCURRENCY_CONFLICT,
                "the confirmed root changed while the package was being verified",
                {"prepared_root": plan.pre.root_version, "current_root": meta["root_version"],
                 "prepared_digest": plan.pre.root_digest, "current_digest": meta["root_digest"]},
            )
        if meta["trusted_time"] > plan.trusted_time:
            raise UpdateError(
                E_CONCURRENCY_CONFLICT,
                "another writer advanced the trusted-time watermark past this request",
                {"prepared_time": plan.trusted_time, "current_time": meta["trusted_time"]},
            )

        current_channels = self.store.channel_versions(tenant, conn)
        if current_channels != plan.pre.channel_versions:
            changed = sorted(
                set(current_channels) | set(plan.pre.channel_versions)
            )
            raise UpdateError(
                E_CONCURRENCY_CONFLICT,
                "a channel watermark moved while the package was being verified",
                {"prepared": plan.pre.channel_versions, "current": current_channels, "channels": changed},
            )

        current_floors = self.store.target_floors(tenant, conn)
        if current_floors != plan.pre.target_floors:
            raise UpdateError(
                E_CONCURRENCY_CONFLICT,
                "a target watermark moved while the package was being verified",
                {"prepared": plan.pre.target_floors, "current": current_floors},
            )

        # Re-read every input from disk and compare each digest.
        current_digests = PackageReader(plan.package.package_dir).load().all_input_digests()
        if current_digests != plan.input_digests:
            changed = sorted(
                key
                for key in set(current_digests) | set(plan.input_digests)
                if current_digests.get(key) != plan.input_digests.get(key)
            )
            raise UpdateError(
                E_CONCURRENCY_CONFLICT,
                "package input digests changed between verification and commit",
                {"changed": changed},
            )

        # Time windows must still hold against this trusted time.
        for step in plan.root_steps:
            _within(step.new_root, plan.trusted_time, E_ROOT_EXPIRED, E_ROOT_NOT_YET_VALID, "root")
        for snap in plan.snapshots:
            _within(snap.doc, plan.trusted_time, E_SNAPSHOT_EXPIRED, E_SNAPSHOT_NOT_YET_VALID, "snapshot")
        for target in plan.targets:
            _within(target.doc, plan.trusted_time, E_TARGET_EXPIRED, E_TARGET_NOT_YET_VALID, "target")

        # No signature record may be consumed twice.
        for record in _claim_records(plan):
            if self.store.signature_seen(
                conn, tenant, record["key_id"], record["gen"], record["nonce"]
            ):
                raise UpdateError(
                    E_SIGNATURE_REPLAY,
                    "a signature record has already been consumed",
                    {"key_id": record["key_id"], "gen": record["gen"], "nonce": record["nonce"]},
                )

    # -- receipt -----------------------------------------------------------
    def _build_receipt(self, plan: UpdatePlan) -> dict:
        channels_after = {}
        for snap in plan.snapshots:
            channels_after[snap.doc["channel"]] = {
                "version": snap.doc["version"],
                "snapshot_digest": snap.digest,
                "root_version": snap.doc["root_version"],
            }
        targets_after = {}
        for target in plan.targets:
            targets_after[target.doc["target_id"]] = {
                "version": target.doc["version"],
                "channel": target.doc["channel"],
                "path": target.doc["path"],
                "file_digest": target.file_digest,
                "file_size": target.file_size,
            }
        body = {
            "tenant": plan.tenant,
            "request_id": plan.request_id,
            "package_digest": plan.package_digest,
            "trusted_time": plan.trusted_time,
            "root_before": {"version": plan.root_before["version"], "digest": doc_digest(plan.root_before)},
            "root_after": {"version": plan.root_after["version"], "digest": doc_digest(plan.root_after)},
            "root_steps": len(plan.root_steps),
            "channels": channels_after,
            "targets": targets_after,
            "noops": plan.noops,
            "trust_table": plan.trust_table(),
        }
        body["receipt_digest"] = digest_json(body)
        return body
