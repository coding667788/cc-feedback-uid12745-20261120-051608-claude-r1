"""Shared fixtures: build a live tenant, packages and a temporary store.

These helpers build *real* packages on disk - no mocks - because the point of
the test suite is the on-disk artefact and the SQLite transaction boundary.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from solution.builder import Domain, Session, write_package  # noqa: E402
from solution.canonical import digest_json, sha256_hex  # noqa: E402
from solution.docs import doc_digest  # noqa: E402
from solution.state import Store  # noqa: E402
from solution.updater import Updater  # noqa: E402


def secret(tag: str) -> str:
    return sha256_hex(("simupd-test-key:" + tag).encode("utf-8"))


TENANT = "tenant-test"
CHANNEL = "stable"
TAG = "core"

DEFAULT_HOLDERS = {
    "root-a": {"role": "root", "keys": {"a1": secret("a1")}},
    "root-b": {"role": "root", "keys": {"b1": secret("b1")}},
    "root-c": {"role": "root", "keys": {"c1": secret("c1"), "c2": secret("c2")}},
    "root-d": {"role": "root", "keys": {"d1": secret("d1")}},
    "snap-1": {"role": "snapshot", "keys": {"s1": secret("s1")}},
    "snap-2": {"role": "snapshot", "keys": {"s2": secret("s2")}},
    "snap-3": {"role": "snapshot", "keys": {"s3": secret("s3")}},
    "tgt-1": {"role": "target", "keys": {"t1": secret("t1")}},
    "tgt-2": {"role": "target", "keys": {"t2": secret("t2")}},
    "tgt-3": {"role": "target", "keys": {"t3": secret("t3")}},
}

ROOT_ROLE = {"holders": ["root-a", "root-b", "root-c"], "threshold": 2}
SNAP_ROLE = {"holders": ["snap-1", "snap-2"], "threshold": 2, "tags": [TAG], "paths": ["app", "lib"]}
TGT_ROLE = {"holders": ["tgt-1", "tgt-2"], "threshold": 2, "tags": [TAG], "paths": ["app/services", "lib/core"]}


def domain(names=None) -> Domain:
    names = names or list(DEFAULT_HOLDERS)
    return Domain({"tenant": TENANT, "holders": {n: DEFAULT_HOLDERS[n] for n in names}})


def root_v1(**overrides) -> dict:
    body = {
        "version": 1,
        "issued_at": 1000,
        "expires_at": 9000,
        "root": dict(ROOT_ROLE),
        "snapshot": dict(SNAP_ROLE),
        "target": dict(TGT_ROLE),
        "sign": [
            {"holder": "root-a", "key": "a1"},
            {"holder": "root-b", "key": "b1"},
        ],
    }
    body.update(overrides)
    return body


def root_v2(**overrides) -> dict:
    body = {
        "version": 2,
        "issued_at": 1100,
        "expires_at": 9200,
        "root": {"holders": ["root-c", "root-d", "root-a"], "threshold": 2},
        "snapshot": dict(SNAP_ROLE),
        "target": dict(TGT_ROLE),
        "sign": [
            {"holder": "root-a", "key": "a1"},
            {"holder": "root-b", "key": "b1"},
            {"holder": "root-c", "key": "c1"},
            {"holder": "root-d", "key": "d1"},
        ],
    }
    body.update(overrides)
    return body


def target_spec(target_id: str, version: int, **overrides) -> dict:
    body = {
        "id": target_id,
        "version": version,
        "root_version": 1,
        "snapshot_version": 1,
        "channel": CHANNEL,
        "purpose": "runtime",
        "repo_tag": TAG,
        "path": f"app/services/{target_id}.bin",
        "payload": f"text:{target_id}-v{version}",
        "issued_at": 1000,
        "expires_at": 8000,
        "sign": [
            {"holder": "tgt-1", "key": "t1"},
            {"holder": "tgt-2", "key": "t2"},
        ],
    }
    body.update(overrides)
    return body


def snapshot_spec(version: int, entries, **overrides) -> dict:
    body = {
        "channel": CHANNEL,
        "version": version,
        "root_version": 1,
        "repo_tag": TAG,
        "issued_at": 1000,
        "expires_at": 8000,
        "entries": entries,
        "sign": [
            {"holder": "snap-1", "key": "s1"},
            {"holder": "snap-2", "key": "s2"},
        ],
    }
    body.update(overrides)
    return body


def policy(role: str, holders, threshold: int, *, tags=None, paths=None, revoked=None) -> dict:
    """Build a *materialised* role policy (holders map to their real key ids)."""
    keys_by_holder = {}
    for holder in holders:
        keys_by_holder[holder] = sorted(DEFAULT_HOLDERS[holder]["keys"])
    return {
        "threshold": threshold,
        "holders": keys_by_holder,
        "revoked": list(revoked or []),
        "tags": list(tags or ["*"]),
        "paths": list(paths or ["*"]),
    }


def with_role(root: dict, role: str, materialised: dict) -> dict:
    import copy

    clone = copy.deepcopy(root)
    clone["roles"][role] = materialised
    return clone


class TenantHarness(unittest.TestCase):
    """A temporary tenant with a bootstrapped v1 root and a fresh package dir."""

    root_version = 1

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="simupd-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db_path = os.path.join(self.tmp, "state.db")
        self.package_root = os.path.join(self.tmp, "packages")
        os.makedirs(self.package_root, exist_ok=True)
        self.domain = domain()
        self.session = Session(self.domain, self._testMethodName)
        self.store = Store(self.db_path)
        self.updater = Updater(self.store)
        self.addCleanup(self.store.close)
        self.bootstrap_root = self.session.build_root(root_v1())
        self.store.install_anchor(
            TENANT, self.bootstrap_root, doc_digest(self.bootstrap_root), 1000
        )

    # -- package helpers ---------------------------------------------------
    def write(self, name: str, docs: list, files: dict, **kwargs) -> str:
        package_dir = os.path.join(self.package_root, name)
        if os.path.isdir(package_dir):
            shutil.rmtree(package_dir)
        os.makedirs(package_dir)
        return write_package(package_dir, TENANT, docs, files, **kwargs)

    def build_target(self, target_id: str, version: int, **overrides) -> dict:
        """Build a target and return it with its payload available for writing."""
        spec = target_spec(target_id, version, **overrides)
        doc = self.session.build_target(spec)
        return doc

    def build_snapshot(self, version: int, target_refs, **overrides) -> dict:
        entries = []
        for ref in target_refs:
            tid, ver = ref.split(":") if isinstance(ref, str) else ref
            target = self.session.targets[(tid, int(ver))]
            entries.append(Session.make_entry(target))
        return self.session.build_snapshot(snapshot_spec(version, entries, **overrides), entries)

    def snapshot_for(self, version: int, targets, **overrides) -> dict:
        """Build a snapshot that locks exactly the given target documents."""
        entries = [Session.make_entry(target) for target in targets]
        return self.session.build_snapshot(snapshot_spec(version, entries, **overrides), entries)

    def commit(self, name: str, docs: list, files: dict, trusted_time: int, request_id: str = "req"):
        package_dir = self.write(name, docs, files)
        plan = self.updater.prepare(TENANT, package_dir, request_id, trusted_time)
        return self.updater.publish(plan), plan
