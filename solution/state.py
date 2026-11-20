"""SQLite-backed client state, atomic publish and fixed-version read views.

Design notes
------------
* One database file holds many tenants; every row is tenant-scoped.
* Published artefacts are immutable.  Roots, snapshots, target history and
  content-addressed blobs are append-only, enforced by database triggers.
* A *pointer* may only reference a snapshot row that already exists with the
  matching digest, and a target may only reference a stored blob.  Also
  enforced by triggers, so no code path - not even a buggy one - can publish
  a pointer to something that was never verified.
* ``write_txn`` uses ``BEGIN IMMEDIATE`` so the read-check-write sequence in
  the updater is serialised against other writers.  A racing writer gets a
  deterministic ``E_CONCURRENCY_CONFLICT`` instead of a lost update.
* Read views open a *separate* ``mode=ro`` connection, so a fixed-version
  query never blocks a writer and can never mutate state.
* Every signature record that participates in an accepted quorum is recorded
  in ``signature_claims``.  The primary key makes signature replay a hard
  failure rather than a silent second acceptance.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonical_json, digest_json, sha256_hex
from .errors import (
    E_CONCURRENCY_CONFLICT,
    E_INPUT_INVALID,
    E_ROLLBACK_DETECTED,
    E_SIGNATURE_REPLAY,
    E_STORE_BUSY,
    E_UNKNOWN_TENANT,
    UpdateError,
)

SCHEMA_VERSION = 1
ZERO_DIGEST = "0" * 64


def default_busy_timeout_ms() -> int:
    return int(os.environ.get("SIMUPD_BUSY_TIMEOUT_MS", "10000"))


def _readonly_uri(path: str) -> str:
    """Build a SQLite URI that forces read-only access."""
    return Path(os.path.abspath(path)).as_uri() + "?mode=ro"


@dataclass(frozen=True)
class PreState:
    """The exact state a verification was prepared against.

    ``root_doc`` is captured in the same read transaction as the watermarks so
    that "which root am I verifying against" and "what watermarks will I
    recheck" can never disagree.
    """

    tenant: str
    root_version: int
    root_digest: str
    channel_versions: dict
    target_floors: dict
    trusted_time: int
    root_doc: dict

    def as_dict(self) -> dict:
        return {
            "tenant": self.tenant,
            "root_version": self.root_version,
            "root_digest": self.root_digest,
            "channel_versions": dict(sorted(self.channel_versions.items())),
            "target_floors": dict(sorted(self.target_floors.items())),
            "trusted_time": self.trusted_time,
        }

    def fingerprint(self) -> str:
        return digest_json(self.as_dict())


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant       TEXT PRIMARY KEY,
    trusted_time INTEGER NOT NULL,
    root_version INTEGER NOT NULL,
    root_digest  TEXT NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS roots (
    tenant   TEXT    NOT NULL,
    version  INTEGER NOT NULL,
    digest   TEXT    NOT NULL,
    doc      BLOB    NOT NULL,
    added_at INTEGER NOT NULL,
    PRIMARY KEY (tenant, version)
);

CREATE TABLE IF NOT EXISTS snapshots (
    tenant       TEXT    NOT NULL,
    channel      TEXT    NOT NULL,
    version      INTEGER NOT NULL,
    digest       TEXT    NOT NULL,
    root_version INTEGER NOT NULL,
    doc          BLOB    NOT NULL,
    published_at INTEGER NOT NULL,
    PRIMARY KEY (tenant, channel, version)
);

CREATE TABLE IF NOT EXISTS channels (
    tenant          TEXT    NOT NULL,
    channel         TEXT    NOT NULL,
    version         INTEGER NOT NULL,
    snapshot_digest TEXT    NOT NULL,
    PRIMARY KEY (tenant, channel)
);

CREATE TABLE IF NOT EXISTS target_history (
    tenant      TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    channel     TEXT    NOT NULL,
    purpose     TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    file_digest TEXT    NOT NULL,
    file_size   INTEGER NOT NULL,
    doc_digest  TEXT    NOT NULL,
    published_at INTEGER NOT NULL,
    PRIMARY KEY (tenant, target_id, version)
);

CREATE TABLE IF NOT EXISTS targets (
    tenant      TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    channel     TEXT    NOT NULL,
    purpose     TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    file_digest TEXT    NOT NULL,
    file_size   INTEGER NOT NULL,
    doc_digest  TEXT    NOT NULL,
    PRIMARY KEY (tenant, target_id)
);

CREATE TABLE IF NOT EXISTS blobs (
    tenant  TEXT    NOT NULL,
    digest  TEXT    NOT NULL,
    size    INTEGER NOT NULL,
    content BLOB    NOT NULL,
    PRIMARY KEY (tenant, digest)
);

CREATE TABLE IF NOT EXISTS signature_claims (
    tenant  TEXT    NOT NULL,
    key_id  TEXT    NOT NULL,
    gen     INTEGER NOT NULL,
    nonce   TEXT    NOT NULL,
    PRIMARY KEY (tenant, key_id, gen, nonce)
);

CREATE TABLE IF NOT EXISTS receipts (
    tenant         TEXT    NOT NULL,
    request_id     TEXT    NOT NULL,
    package_digest TEXT    NOT NULL,
    receipt_json   TEXT    NOT NULL,
    committed_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant, request_id)
);

-- ---- immutability guards ------------------------------------------------
CREATE TRIGGER IF NOT EXISTS roots_immutable
BEFORE UPDATE ON roots BEGIN SELECT RAISE(ABORT, 'roots are immutable'); END;

CREATE TRIGGER IF NOT EXISTS snapshots_immutable
BEFORE UPDATE ON snapshots BEGIN SELECT RAISE(ABORT, 'snapshots are immutable'); END;

CREATE TRIGGER IF NOT EXISTS target_history_immutable
BEFORE UPDATE ON target_history BEGIN SELECT RAISE(ABORT, 'target history is immutable'); END;

CREATE TRIGGER IF NOT EXISTS blobs_immutable
BEFORE UPDATE ON blobs BEGIN SELECT RAISE(ABORT, 'blobs are immutable'); END;

CREATE TRIGGER IF NOT EXISTS signature_claims_immutable
BEFORE UPDATE ON signature_claims BEGIN SELECT RAISE(ABORT, 'signature claims are immutable'); END;

-- ---- pointer integrity --------------------------------------------------
CREATE TRIGGER IF NOT EXISTS channels_pointer_insert
BEFORE INSERT ON channels
WHEN NOT EXISTS (
  SELECT 1 FROM snapshots s
  WHERE s.tenant = NEW.tenant AND s.channel = NEW.channel
    AND s.version = NEW.version AND s.digest = NEW.snapshot_digest
) BEGIN SELECT RAISE(ABORT, 'pointer to an unverified snapshot'); END;

CREATE TRIGGER IF NOT EXISTS channels_pointer_update
BEFORE UPDATE ON channels
WHEN NOT EXISTS (
  SELECT 1 FROM snapshots s
  WHERE s.tenant = NEW.tenant AND s.channel = NEW.channel
    AND s.version = NEW.version AND s.digest = NEW.snapshot_digest
) BEGIN SELECT RAISE(ABORT, 'pointer to an unverified snapshot'); END;

CREATE TRIGGER IF NOT EXISTS targets_blob_insert
BEFORE INSERT ON targets
WHEN NOT EXISTS (
  SELECT 1 FROM blobs b WHERE b.tenant = NEW.tenant
    AND b.digest = NEW.file_digest AND b.size = NEW.file_size
) BEGIN SELECT RAISE(ABORT, 'target points at an unstored blob'); END;

CREATE TRIGGER IF NOT EXISTS targets_blob_update
BEFORE UPDATE ON targets
WHEN NOT EXISTS (
  SELECT 1 FROM blobs b WHERE b.tenant = NEW.tenant
    AND b.digest = NEW.file_digest AND b.size = NEW.file_size
) BEGIN SELECT RAISE(ABORT, 'target points at an unstored blob'); END;

CREATE TRIGGER IF NOT EXISTS target_history_blob_insert
BEFORE INSERT ON target_history
WHEN NOT EXISTS (
  SELECT 1 FROM blobs b WHERE b.tenant = NEW.tenant
    AND b.digest = NEW.file_digest AND b.size = NEW.file_size
) BEGIN SELECT RAISE(ABORT, 'target history points at an unstored blob'); END;
"""


class Store:
    """Writer-facing connection pool (one connection per thread)."""

    def __init__(self, db_path: str, *, busy_timeout_ms: int | None = None) -> None:
        self.db_path = os.path.abspath(db_path)
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._local = threading.local()
        self.busy_timeout_ms = busy_timeout_ms if busy_timeout_ms is not None else default_busy_timeout_ms()
        conn = self._conn()
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        conn.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)

    # -- connections -------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path, timeout=self.busy_timeout_ms / 1000.0, isolation_level=None
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA busy_timeout = %d" % self.busy_timeout_ms)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @contextmanager
    def read_txn(self):
        conn = self._conn()
        conn.execute("BEGIN")
        try:
            yield conn
        finally:
            conn.execute("COMMIT")

    @contextmanager
    def write_txn(self, *, durable: bool = True):
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise UpdateError(E_STORE_BUSY, "could not acquire the write lock", {"reason": str(exc)}) from None
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            if not durable:
                conn.execute("ROLLBACK")
                return
            try:
                conn.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                conn.execute("ROLLBACK")
                raise UpdateError(E_STORE_BUSY, "commit failed", {"reason": str(exc)}) from None

    # -- bootstrap ---------------------------------------------------------
    def install_anchor(self, tenant: str, root_doc: dict, root_digest: str, trusted_time: int) -> None:
        """Record the out-of-band trust anchor for ``tenant`` exactly once."""
        with self.write_txn() as conn:
            existing = conn.execute("SELECT * FROM tenants WHERE tenant = ?", (tenant,)).fetchone()
            if existing is not None:
                if existing["root_version"] != root_doc["version"] or existing["root_digest"] != root_digest:
                    raise UpdateError(
                        E_CONCURRENCY_CONFLICT,
                        "tenant is already initialised with a different anchor",
                        {"tenant": tenant},
                    )
                return
            conn.execute(
                "INSERT INTO roots(tenant, version, digest, doc, added_at) VALUES (?,?,?,?,?)",
                (tenant, root_doc["version"], root_digest, canonical_json(root_doc), trusted_time),
            )
            conn.execute(
                "INSERT INTO tenants(tenant, trusted_time, root_version, root_digest, updated_at) VALUES (?,?,?,?,?)",
                (tenant, trusted_time, root_doc["version"], root_digest, trusted_time),
            )

    # -- reads -------------------------------------------------------------
    def tenant_meta(self, tenant: str, conn: sqlite3.Connection | None = None) -> dict:
        conn = conn or self._conn()
        row = conn.execute("SELECT * FROM tenants WHERE tenant = ?", (tenant,)).fetchone()
        if row is None:
            raise UpdateError(E_UNKNOWN_TENANT, "tenant has no trust anchor", {"tenant": tenant})
        return dict(row)

    def current_root(self, tenant: str, conn: sqlite3.Connection | None = None) -> dict:
        conn = conn or self._conn()
        meta = self.tenant_meta(tenant, conn)
        row = conn.execute(
            "SELECT doc FROM roots WHERE tenant = ? AND version = ?", (tenant, meta["root_version"])
        ).fetchone()
        if row is None:
            raise UpdateError(E_ROLLBACK_DETECTED, "tenant points at a missing root document", {"tenant": tenant})
        return json.loads(bytes(row["doc"]).decode("utf-8"))

    def channel_versions(self, tenant: str, conn: sqlite3.Connection | None = None) -> dict:
        conn = conn or self._conn()
        rows = conn.execute("SELECT channel, version FROM channels WHERE tenant = ?", (tenant,)).fetchall()
        return {row["channel"]: row["version"] for row in rows}

    def target_floors(self, tenant: str, conn: sqlite3.Connection | None = None) -> dict:
        conn = conn or self._conn()
        rows = conn.execute("SELECT target_id, version FROM targets WHERE tenant = ?", (tenant,)).fetchall()
        return {row["target_id"]: row["version"] for row in rows}

    def snapshot_digest(self, tenant: str, channel: str, conn: sqlite3.Connection | None = None) -> str | None:
        conn = conn or self._conn()
        row = conn.execute(
            "SELECT snapshot_digest FROM channels WHERE tenant = ? AND channel = ?", (tenant, channel)
        ).fetchone()
        return None if row is None else row["snapshot_digest"]

    def snapshot_doc(self, tenant: str, channel: str, version: int) -> dict | None:
        with self.read_txn() as conn:
            row = conn.execute(
                "SELECT doc FROM snapshots WHERE tenant = ? AND channel = ? AND version = ?",
                (tenant, channel, version),
            ).fetchone()
        return None if row is None else json.loads(bytes(row["doc"]).decode("utf-8"))

    def target_doc_digest(self, tenant: str, target_id: str, version: int) -> str | None:
        row = self._conn().execute(
            "SELECT doc_digest FROM target_history WHERE tenant = ? AND target_id = ? AND version = ?",
            (tenant, target_id, version),
        ).fetchone()
        return None if row is None else row["doc_digest"]

    def target_file_digest(self, tenant: str, target_id: str, version: int) -> str | None:
        row = self._conn().execute(
            "SELECT file_digest FROM target_history WHERE tenant = ? AND target_id = ? AND version = ?",
            (tenant, target_id, version),
        ).fetchone()
        return None if row is None else row["file_digest"]

    def receipt(self, tenant: str, request_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        conn = conn or self._conn()
        row = conn.execute(
            "SELECT package_digest, receipt_json FROM receipts WHERE tenant = ? AND request_id = ?",
            (tenant, request_id),
        ).fetchone()
        if row is None:
            return None
        receipt = json.loads(row["receipt_json"])
        receipt["package_digest"] = row["package_digest"]
        return receipt

    def signature_seen(self, conn: sqlite3.Connection, tenant: str, key_id: str, gen: int, nonce: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM signature_claims WHERE tenant = ? AND key_id = ? AND gen = ? AND nonce = ?",
            (tenant, key_id, gen, nonce),
        ).fetchone()
        return row is not None

    def pre_state(self, tenant: str, conn: sqlite3.Connection | None = None) -> PreState:
        """Read the root, watermarks and floors as ONE consistent snapshot.

        Without an explicit read transaction SQLite would still give us
        statement-level consistency, but three separate statements could each
        observe a different committed state.  ``BEGIN`` (deferred) pins the
        snapshot for the whole read, which is what the updater's prepare
        phase needs.
        """
        if conn is not None:
            return self._pre_state_locked(tenant, conn)
        conn = self._conn()
        conn.execute("BEGIN")
        try:
            return self._pre_state_locked(tenant, conn)
        finally:
            conn.execute("COMMIT")

    def _pre_state_locked(self, tenant: str, conn: sqlite3.Connection) -> PreState:
        meta = self.tenant_meta(tenant, conn)
        root_row = conn.execute(
            "SELECT digest, doc FROM roots WHERE tenant = ? AND version = ?",
            (tenant, meta["root_version"]),
        ).fetchone()
        if root_row is None:
            raise UpdateError(
                E_ROLLBACK_DETECTED, "tenant points at a missing root document", {"tenant": tenant}
            )
        root_doc = json.loads(bytes(root_row["doc"]).decode("utf-8"))
        return PreState(
            tenant=tenant,
            root_version=meta["root_version"],
            root_digest=meta["root_digest"],
            channel_versions=self.channel_versions(tenant, conn),
            target_floors=self.target_floors(tenant, conn),
            trusted_time=meta["trusted_time"],
            root_doc=root_doc,
        )

    # -- writes (must be called inside write_txn) --------------------------
    def put_root(self, conn, tenant: str, root_doc: dict, digest: str, at: int) -> None:
        existing = conn.execute(
            "SELECT digest FROM roots WHERE tenant = ? AND version = ?", (tenant, root_doc["version"])
        ).fetchone()
        if existing is not None:
            if existing["digest"] != digest:
                raise UpdateError(
                    E_ROLLBACK_DETECTED,
                    "a different root document already occupies this version",
                    {"version": root_doc["version"]},
                )
            return
        conn.execute(
            "INSERT INTO roots(tenant, version, digest, doc, added_at) VALUES (?,?,?,?,?)",
            (tenant, root_doc["version"], digest, canonical_json(root_doc), at),
        )

    def put_snapshot(self, conn, tenant: str, snapshot: dict, digest: str, at: int) -> None:
        existing = conn.execute(
            "SELECT digest FROM snapshots WHERE tenant = ? AND channel = ? AND version = ?",
            (tenant, snapshot["channel"], snapshot["version"]),
        ).fetchone()
        if existing is not None:
            if existing["digest"] != digest:
                raise UpdateError(
                    E_ROLLBACK_DETECTED,
                    "a different snapshot already occupies this channel version",
                    {"channel": snapshot["channel"], "version": snapshot["version"]},
                )
            return
        conn.execute(
            "INSERT INTO snapshots(tenant, channel, version, digest, root_version, doc, published_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                tenant,
                snapshot["channel"],
                snapshot["version"],
                digest,
                snapshot["root_version"],
                canonical_json(snapshot),
                at,
            ),
        )

    def put_blob(self, conn, tenant: str, digest: str, content: bytes) -> None:
        if sha256_hex(content) != digest:
            raise UpdateError(E_ROLLBACK_DETECTED, "refusing to store a blob under the wrong digest", {"digest": digest})
        existing = conn.execute(
            "SELECT content FROM blobs WHERE tenant = ? AND digest = ?", (tenant, digest)
        ).fetchone()
        if existing is not None:
            if bytes(existing["content"]) != content:
                raise UpdateError(E_ROLLBACK_DETECTED, "stored blob does not match its digest", {"digest": digest})
            return
        conn.execute(
            "INSERT INTO blobs(tenant, digest, size, content) VALUES (?,?,?,?)",
            (tenant, digest, len(content), content),
        )

    def put_target(self, conn, tenant: str, target: dict, doc_digest: str, at: int) -> None:
        row = (
            tenant,
            target["target_id"],
            target["version"],
            target["channel"],
            target["purpose"],
            target["path"],
            target["file"]["digest"],
            target["file"]["size"],
            doc_digest,
        )
        conn.execute(
            "INSERT OR IGNORE INTO target_history(tenant, target_id, version, channel, purpose, path, "
            "file_digest, file_size, doc_digest, published_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            row + (at,),
        )
        conn.execute(
            "INSERT INTO targets(tenant, target_id, version, channel, purpose, path, file_digest, "
            "file_size, doc_digest) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(tenant, target_id) DO UPDATE SET version=excluded.version, "
            "channel=excluded.channel, purpose=excluded.purpose, path=excluded.path, "
            "file_digest=excluded.file_digest, file_size=excluded.file_size, doc_digest=excluded.doc_digest",
            row,
        )

    def put_channel_pointer(self, conn, tenant: str, channel: str, version: int, snapshot_digest: str) -> None:
        conn.execute(
            "INSERT INTO channels(tenant, channel, version, snapshot_digest) VALUES (?,?,?,?) "
            "ON CONFLICT(tenant, channel) DO UPDATE SET version=excluded.version, "
            "snapshot_digest=excluded.snapshot_digest",
            (tenant, channel, version, snapshot_digest),
        )

    def put_tenant_meta(self, conn, tenant: str, trusted_time: int, root_version: int, root_digest: str) -> None:
        conn.execute(
            "UPDATE tenants SET trusted_time = ?, root_version = ?, root_digest = ?, updated_at = ? WHERE tenant = ?",
            (trusted_time, root_version, root_digest, trusted_time, tenant),
        )

    def put_receipt(self, conn, tenant: str, request_id: str, package_digest: str, receipt: dict, at: int) -> None:
        conn.execute(
            "INSERT INTO receipts(tenant, request_id, package_digest, receipt_json, committed_at) VALUES (?,?,?,?,?)",
            (tenant, request_id, package_digest, json.dumps(receipt, sort_keys=True), at),
        )

    def claim_signatures(self, conn, tenant: str, records: list[dict]) -> None:
        for record in records:
            try:
                conn.execute(
                    "INSERT INTO signature_claims(tenant, key_id, gen, nonce) VALUES (?,?,?,?)",
                    (tenant, record["key_id"], record["gen"], record["nonce"]),
                )
            except sqlite3.IntegrityError:
                raise UpdateError(
                    E_SIGNATURE_REPLAY,
                    "a signature record has already been consumed",
                    {"key_id": record["key_id"], "gen": record["gen"], "nonce": record["nonce"]},
                ) from None

    # -- audit -------------------------------------------------------------
    def audit(self, tenant: str) -> dict:
        """Recheck the anti-rollback watermark and pointer/blob consistency."""
        with self.read_txn() as conn:
            meta = self.tenant_meta(tenant, conn)
            problems: list[str] = []

            max_root = conn.execute(
                "SELECT MAX(version) AS v FROM roots WHERE tenant = ?", (tenant,)
            ).fetchone()["v"]
            if max_root != meta["root_version"]:
                problems.append(f"root watermark {meta['root_version']} != max stored root {max_root}")
            anchor = conn.execute(
                "SELECT digest FROM roots WHERE tenant = ? AND version = ?", (tenant, meta["root_version"])
            ).fetchone()
            if anchor is None or anchor["digest"] != meta["root_digest"]:
                problems.append("root digest watermark does not match the stored root")

            channels = conn.execute("SELECT * FROM channels WHERE tenant = ?", (tenant,)).fetchall()
            for row in channels:
                max_v = conn.execute(
                    "SELECT MAX(version) AS v FROM snapshots WHERE tenant = ? AND channel = ?",
                    (tenant, row["channel"]),
                ).fetchone()["v"]
                if row["version"] != max_v:
                    problems.append(f"channel {row['channel']} pointer {row['version']} != max history {max_v}")
                snap = conn.execute(
                    "SELECT digest FROM snapshots WHERE tenant = ? AND channel = ? AND version = ?",
                    (tenant, row["channel"], row["version"]),
                ).fetchone()
                if snap is None or snap["digest"] != row["snapshot_digest"]:
                    problems.append(f"channel {row['channel']} points at a missing or mismatched snapshot")

            targets = conn.execute("SELECT * FROM targets WHERE tenant = ?", (tenant,)).fetchall()
            for row in targets:
                max_v = conn.execute(
                    "SELECT MAX(version) AS v FROM target_history WHERE tenant = ? AND target_id = ?",
                    (tenant, row["target_id"]),
                ).fetchone()["v"]
                if row["version"] != max_v:
                    problems.append(f"target {row['target_id']} floor {row['version']} != max history {max_v}")
                hist = conn.execute(
                    "SELECT doc_digest, file_digest, file_size FROM target_history "
                    "WHERE tenant = ? AND target_id = ? AND version = ?",
                    (tenant, row["target_id"], row["version"]),
                ).fetchone()
                if hist is None or hist["doc_digest"] != row["doc_digest"]:
                    problems.append(f"target {row['target_id']} live row disagrees with its history row")
                blob = conn.execute(
                    "SELECT size, content FROM blobs WHERE tenant = ? AND digest = ?",
                    (tenant, row["file_digest"]),
                ).fetchone()
                if blob is None:
                    problems.append(f"target {row['target_id']} points at a missing blob")
                elif sha256_hex(bytes(blob["content"])) != row["file_digest"] or int(blob["size"]) != int(
                    row["file_size"]
                ):
                    problems.append(f"target {row['target_id']} blob content does not match its digest/size")

            if problems:
                raise UpdateError(E_ROLLBACK_DETECTED, "state audit failed", {"problems": problems, "tenant": tenant})
            return {
                "tenant": tenant,
                "root_version": meta["root_version"],
                "root_digest": meta["root_digest"],
                "channel_versions": {row["channel"]: row["version"] for row in channels},
                "target_floors": {row["target_id"]: row["version"] for row in targets},
                "trusted_time": meta["trusted_time"],
                "checked_targets": len(targets),
                "ok": True,
            }

    # -- read-only fixed-version views ------------------------------------
    def _ro_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(_readonly_uri(self.db_path), uri=True, timeout=self.busy_timeout_ms / 1000.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        return conn

    def read_channel(self, tenant: str, channel: str, version: int | None = None) -> dict:
        conn = self._ro_conn()
        try:
            if version is None:
                row = conn.execute(
                    "SELECT c.channel, c.version, c.snapshot_digest, s.root_version, s.doc, s.published_at "
                    "FROM channels c JOIN snapshots s ON s.tenant = c.tenant AND s.channel = c.channel "
                    "AND s.version = c.version WHERE c.tenant = ? AND c.channel = ?",
                    (tenant, channel),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT channel, version, digest AS snapshot_digest, root_version, doc, published_at "
                    "FROM snapshots WHERE tenant = ? AND channel = ? AND version = ?",
                    (tenant, channel, version),
                ).fetchone()
            if row is None:
                raise UpdateError(
                    E_INPUT_INVALID, "no such channel version",
                    {"tenant": tenant, "channel": channel, "version": version},
                )
            return {
                "tenant": tenant,
                "channel": row["channel"],
                "version": row["version"],
                "snapshot_digest": row["snapshot_digest"],
                "root_version": row["root_version"],
                "snapshot": json.loads(bytes(row["doc"]).decode("utf-8")),
                "published_at": row["published_at"],
            }
        finally:
            conn.close()

    def read_target(self, tenant: str, target_id: str, version: int | None = None) -> dict:
        conn = self._ro_conn()
        try:
            if version is None:
                row = conn.execute(
                    "SELECT * FROM targets WHERE tenant = ? AND target_id = ?", (tenant, target_id)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM target_history WHERE tenant = ? AND target_id = ? AND version = ?",
                    (tenant, target_id, version),
                ).fetchone()
            if row is None:
                raise UpdateError(
                    E_INPUT_INVALID, "no such target version",
                    {"tenant": tenant, "target_id": target_id, "version": version},
                )
            blob = conn.execute(
                "SELECT content FROM blobs WHERE tenant = ? AND digest = ?", (tenant, row["file_digest"])
            ).fetchone()
            content = bytes(blob["content"]) if blob is not None else None
            return {
                "tenant": tenant,
                "target_id": row["target_id"],
                "version": row["version"],
                "channel": row["channel"],
                "purpose": row["purpose"],
                "path": row["path"],
                "file_digest": row["file_digest"],
                "file_size": row["file_size"],
                "doc_digest": row["doc_digest"],
                "content_sha256": sha256_hex(content) if content is not None else None,
                "content_matches": content is not None and sha256_hex(content) == row["file_digest"],
            }
        finally:
            conn.close()

    def read_root(self, tenant: str, version: int | None = None) -> dict:
        conn = self._ro_conn()
        try:
            if version is None:
                meta = conn.execute("SELECT root_version FROM tenants WHERE tenant = ?", (tenant,)).fetchone()
                if meta is None:
                    raise UpdateError(E_UNKNOWN_TENANT, "tenant has no trust anchor", {"tenant": tenant})
                version = meta["root_version"]
            row = conn.execute(
                "SELECT version, digest, doc FROM roots WHERE tenant = ? AND version = ?", (tenant, version)
            ).fetchone()
            if row is None:
                raise UpdateError(E_INPUT_INVALID, "no such root version", {"tenant": tenant, "version": version})
            return {
                "tenant": tenant,
                "version": row["version"],
                "digest": row["digest"],
                "root": json.loads(bytes(row["doc"]).decode("utf-8")),
            }
        finally:
            conn.close()
