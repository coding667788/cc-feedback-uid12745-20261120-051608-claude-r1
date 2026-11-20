"""Generate ``cases.json`` deterministically.

Running this module rewrites ``cases.json`` in the repository root.  The file
is committed, so the deliverable stays replayable without regenerating it;
this generator exists so the recipe is auditable and reviewable.
"""

from __future__ import annotations

import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------
# key material
# --------------------------------------------------------------------------
def secret(tag: str) -> str:
    """A deterministic 32-byte simulated secret for a human-readable tag."""
    import hashlib

    return hashlib.sha256(("simupd-key:" + tag).encode("utf-8")).hexdigest()


TENANT = "acme-updates"
CHANNEL = "stable"
REPO_TAG = "core"

HOLDERS = {
    # root role: three holders, two keys each for the "many keys, one seat" case
    "root-alice": ("root", {"alice-k1": secret("alice-k1")}),
    "root-bob": ("root", {"bob-k1": secret("bob-k1")}),
    # root-carol also holds carol-k2 so one holder cannot fill two seats
    "root-carol": ("root", {"carol-k1": secret("carol-k1"), "carol-k2": secret("carol-k2")}),
    "root-dave": ("root", {"dave-k1": secret("dave-k1")}),
    # snapshot role
    "snap-eve": ("snapshot", {"eve-k1": secret("eve-k1")}),
    "snap-frank": ("snapshot", {"frank-k1": secret("frank-k1")}),
    "snap-grace": ("snapshot", {"grace-k1": secret("grace-k1")}),
    # target role
    "tgt-heidi": ("target", {"heidi-k1": secret("heidi-k1")}),
    "tgt-ivan": ("target", {"ivan-k1": secret("ivan-k1")}),
    "tgt-judy": ("target", {"judy-k1": secret("judy-k1")}),
}


def holders_spec(names):
    return {name: {"role": HOLDERS[name][0], "keys": dict(HOLDERS[name][1])} for name in names}


def tenant_spec(names) -> dict:
    return {"tenant": TENANT, "holders": holders_spec(names)}


# --------------------------------------------------------------------------
# reusable fragments
# --------------------------------------------------------------------------
ROOT_ROLE = {"holders": ["root-alice", "root-bob", "root-carol"], "threshold": 2}
SNAP_ROLE = {"holders": ["snap-eve", "snap-frank"], "threshold": 2, "tags": [REPO_TAG], "paths": ["app", "lib"]}
TGT_ROLE = {
    "holders": ["tgt-heidi", "tgt-ivan"],
    "threshold": 2,
    "tags": [REPO_TAG],
    "paths": ["app/services", "lib/core"],
}


def root_v1() -> dict:
    return {
        "version": 1,
        "issued_at": 1000,
        "expires_at": 9000,
        "root": dict(ROOT_ROLE),
        "snapshot": dict(SNAP_ROLE),
        "target": dict(TGT_ROLE),
        "sign": [
            {"holder": "root-alice", "key": "alice-k1"},
            {"holder": "root-bob", "key": "bob-k1"},
        ],
    }


def root_v2() -> dict:
    """Rotate: alice+bob leave, carol+dave stay/join.  Both quorums met."""
    return {
        "version": 2,
        "issued_at": 1100,
        "expires_at": 9200,
        "root": {"holders": ["root-carol", "root-dave", "root-alice"], "threshold": 2},
        "snapshot": dict(SNAP_ROLE),
        "target": dict(TGT_ROLE),
        "sign": [
            # old quorum: alice + bob
            {"holder": "root-alice", "key": "alice-k1"},
            {"holder": "root-bob", "key": "bob-k1"},
            # new quorum: carol + dave
            {"holder": "root-carol", "key": "carol-k1"},
            {"holder": "root-dave", "key": "dave-k1"},
        ],
    }


def root_v3() -> dict:
    """Second rotation: bob rejoins, carol leaves."""
    return {
        "version": 3,
        "issued_at": 1200,
        "expires_at": 9400,
        "root": {"holders": ["root-alice", "root-dave", "root-bob"], "threshold": 2},
        "snapshot": dict(SNAP_ROLE),
        "target": dict(TGT_ROLE),
        "sign": [
            # old quorum: carol + dave
            {"holder": "root-carol", "key": "carol-k1"},
            {"holder": "root-dave", "key": "dave-k1"},
            # new quorum: alice + bob
            {"holder": "root-alice", "key": "alice-k1"},
            {"holder": "root-bob", "key": "bob-k1"},
        ],
    }


def target_spec(target_id, version, *, root_version, snapshot_version, payload, path, purpose="runtime"):
    return {
        "id": target_id,
        "version": version,
        "root_version": root_version,
        "snapshot_version": snapshot_version,
        "channel": CHANNEL,
        "purpose": purpose,
        "repo_tag": REPO_TAG,
        "path": path,
        "payload": payload,
        "issued_at": 1000 + version,
        "expires_at": 8000,
        "sign": [
            {"holder": "tgt-heidi", "key": "heidi-k1"},
            {"holder": "tgt-ivan", "key": "ivan-k1"},
        ],
    }


def snapshot_spec(version, *, root_version, entries, issued_at=1000, expires_at=8000):
    return {
        "channel": CHANNEL,
        "version": version,
        "root_version": root_version,
        "repo_tag": REPO_TAG,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "entries": entries,
        "sign": [
            {"holder": "snap-eve", "key": "eve-k1"},
            {"holder": "snap-frank", "key": "frank-k1"},
        ],
    }


# --------------------------------------------------------------------------
# the cases
# --------------------------------------------------------------------------
def build_cases() -> dict:
    cases = []

    # ---------------------------------------------------------------- 1
    cases.append(
        {
            "name": "01-happy-two-rotations",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "rotations and two targets",
                    "kind": "update",
                    "package_name": "pkg-01",
                    "trusted_time": 1300,
                    "request_id": "req-01",
                    "build": {
                        "roots": [root_v2(), root_v3()],
                        "targets": [
                            target_spec("svc-a", 1, root_version=3, snapshot_version=1,
                                        payload="text:svc-a-v1", path="app/services/svc-a.bin"),
                            target_spec("lib-c", 1, root_version=3, snapshot_version=1,
                                        payload="text:lib-c-v1", path="lib/core/lib-c.so"),
                        ],
                        "snapshots": [
                            snapshot_spec(1, root_version=3, entries=[
                                {"target": "svc-a:1"}, {"target": "lib-c:1"},
                            ]),
                        ],
                        "documents": ["root:2", "root:3", "snapshot:stable:1", "target:svc-a:1", "target:lib-c:1"],
                    },
                    "expect": {
                        "status": "committed",
                        "root_version": 3,
                        "root_steps": 2,
                        "channels": {"stable": 1},
                        "targets": {"svc-a": 1, "lib-c": 1},
                    },
                },
                {"kind": "query", "query": {"kind": "audit"}, "expect": {"ok": True, "root_version": 3}},
            ],
        }
    )

    # ---------------------------------------------------------------- 2
    cases.append(
        {
            "name": "02-reject-root-rollback",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"chain": [root_v1()], "root": root_v2(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "offer v1 after v2",
                    "kind": "update",
                    "package_name": "pkg-02",
                    "trusted_time": 1300,
                    "request_id": "req-02",
                    "build": {
                        "roots": [],
                        "targets": [],
                        "snapshots": [],
                        "documents": ["root:1"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_ROOT_ROLLBACK"},
                },
                {"kind": "query", "query": {"kind": "audit"}, "expect": {"ok": True, "root_version": 2}},
            ],
        }
    )

    # ---------------------------------------------------------------- 3
    cases.append(
        {
            "name": "03-reject-old-root-quorum-missing",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "v2 signed only by the new role",
                    "kind": "update",
                    "package_name": "pkg-03",
                    "trusted_time": 1300,
                    "request_id": "req-03",
                    "build": {
                        "roots": [
                            {
                                "version": 2,
                                "issued_at": 1100,
                                "expires_at": 9200,
                                "root": {"holders": ["root-carol", "root-dave"], "threshold": 2},
                                "snapshot": dict(SNAP_ROLE),
                                "target": dict(TGT_ROLE),
                                "sign": [
                                    {"holder": "root-carol", "key": "carol-k1"},
                                    {"holder": "root-dave", "key": "dave-k1"},
                                ],
                            }
                        ],
                        "targets": [],
                        "snapshots": [],
                        "documents": ["root:2"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_ROOT_OLD_THRESHOLD"},
                },
                {"kind": "query", "query": {"kind": "audit"}, "expect": {"ok": True, "root_version": 1}},
            ],
        }
    )

    # ---------------------------------------------------------------- 4
    cases.append(
        {
            "name": "04-reject-shared-holder-fills-both-seats",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "alice tries to be the old and the new quorum",
                    "kind": "update",
                    "package_name": "pkg-04",
                    "trusted_time": 1300,
                    "request_id": "req-04",
                    "build": {
                        "roots": [
                            {
                                "version": 2,
                                "issued_at": 1100,
                                "expires_at": 9200,
                                "root": {"holders": ["root-alice", "root-bob"], "threshold": 2},
                                "snapshot": dict(SNAP_ROLE),
                                "target": dict(TGT_ROLE),
                                "sign": [
                                    {"holder": "root-alice", "key": "alice-k1"},
                                    {"holder": "root-bob", "key": "bob-k1"},
                                ],
                            }
                        ],
                        "targets": [],
                        "snapshots": [],
                        "documents": ["root:2"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_ROOT_NEW_THRESHOLD"},
                },
            ],
        }
    )

    # ---------------------------------------------------------------- 5
    cases.append(
        {
            "name": "05-reject-duplicate-key-one-seat",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "carol signs twice with two keys; still one holder",
                    "kind": "update",
                    "package_name": "pkg-05",
                    "trusted_time": 1300,
                    "request_id": "req-05",
                    "build": {
                        "targets": [
                            {
                                **target_spec("svc-a", 1, root_version=1, snapshot_version=1,
                                              payload="text:svc-a", path="app/services/svc-a.bin"),
                                "sign": [
                                    {"holder": "tgt-heidi", "key": "heidi-k1"},
                                    {"holder": "tgt-heidi", "key": "heidi-k1", "gen": 2},
                                ],
                            }
                        ],
                        "roots": [],
                        "snapshots": [
                            snapshot_spec(1, root_version=1, entries=[{"target": "svc-a:1"}]),
                        ],
                        "documents": ["snapshot:stable:1", "target:svc-a:1"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_TARGET_THRESHOLD"},
                },
                {"kind": "query", "query": {"kind": "audit"}, "expect": {"ok": True, "checked_targets": 0}},
            ],
        }
    )

    # ---------------------------------------------------------------- 6
    cases.append(
        {
            "name": "06-reject-target-version-floor",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "publish v1",
                    "kind": "update",
                    "package_name": "pkg-06a",
                    "trusted_time": 1100,
                    "request_id": "req-06a",
                    "build": {
                        "roots": [],
                        "targets": [
                            target_spec("svc-a", 1, root_version=1, snapshot_version=1,
                                        payload="text:a1", path="app/services/svc-a.bin"),
                        ],
                        "snapshots": [snapshot_spec(1, root_version=1, entries=[{"target": "svc-a:1"}])],
                        "documents": ["snapshot:stable:1", "target:svc-a:1"],
                    },
                    "expect": {"status": "committed", "targets": {"svc-a": 1}},
                },
                {
                    "label": "publish v2",
                    "kind": "update",
                    "package_name": "pkg-06b",
                    "trusted_time": 1150,
                    "request_id": "req-06b",
                    "build": {
                        "roots": [],
                        "targets": [
                            target_spec("svc-a", 2, root_version=1, snapshot_version=2,
                                        payload="text:a2", path="app/services/svc-a.bin"),
                        ],
                        "snapshots": [snapshot_spec(2, root_version=1, entries=[{"target": "svc-a:2"}])],
                        "documents": ["snapshot:stable:2", "target:svc-a:2"],
                    },
                    "expect": {"status": "committed", "targets": {"svc-a": 2}},
                },
                {
                    "label": "then offer v1 again",
                    "kind": "update",
                    "package_name": "pkg-06c",
                    "trusted_time": 1200,
                    "request_id": "req-06c",
                    "build": {
                        "roots": [],
                        "targets": [
                            {
                                **target_spec("svc-a", 1, root_version=1, snapshot_version=1,
                                              payload="text:a1", path="app/services/svc-a.bin"),
                                "sign": [
                                    {"holder": "tgt-heidi", "key": "heidi-k1"},
                                    {"holder": "tgt-ivan", "key": "ivan-k1"},
                                ],
                            }
                        ],
                        "snapshots": [],
                        "documents": ["target:svc-a:1"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_MANIFEST_VERSION_ROLLBACK"},
                },
            ],
        }
    )

    # ---------------------------------------------------------------- 7
    cases.append(
        {
            "name": "07-allow-republished-old-content-new-signature",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "publish svc-a v1",
                    "kind": "update",
                    "package_name": "pkg-07a",
                    "trusted_time": 1100,
                    "request_id": "req-07a",
                    "build": {
                        "roots": [],
                        "targets": [
                            target_spec("svc-a", 1, root_version=1, snapshot_version=1,
                                        payload="text:same-bytes", path="app/services/svc-a.bin"),
                        ],
                        "snapshots": [snapshot_spec(1, root_version=1, entries=[{"target": "svc-a:1"}])],
                        "documents": ["snapshot:stable:1", "target:svc-a:1"],
                    },
                    "expect": {"status": "committed", "targets": {"svc-a": 1}},
                },
                {
                    "label": "re-issue identical bytes as v2 with a fresh signature",
                    "kind": "update",
                    "package_name": "pkg-07b",
                    "trusted_time": 1200,
                    "request_id": "req-07b",
                    "build": {
                        "roots": [],
                        "targets": [
                            target_spec("svc-a", 2, root_version=1, snapshot_version=2,
                                        payload="text:same-bytes", path="app/services/svc-a.bin"),
                        ],
                        "snapshots": [
                            snapshot_spec(2, root_version=1, entries=[{"target": "svc-a:2"}]),
                        ],
                        "documents": ["snapshot:stable:2", "target:svc-a:2"],
                    },
                    "expect": {"status": "committed", "targets": {"svc-a": 2}},
                },
            ],
        }
    )

    # ---------------------------------------------------------------- 8
    cases.append(
        {
            "name": "08-reject-mixed-snapshot-target",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "target signed for snapshot v1 but snapshot v1 locks something else",
                    "kind": "update",
                    "package_name": "pkg-08",
                    "trusted_time": 1100,
                    "request_id": "req-08",
                    "build": {
                        "roots": [],
                        "targets": [
                            target_spec("svc-a", 1, root_version=1, snapshot_version=1,
                                        payload="text:good", path="app/services/svc-a.bin"),
                        ],
                        "snapshots": [
                            snapshot_spec(1, root_version=1, entries=[
                                {"target": "svc-a:1", "override": {"path": "app/services/other.bin"}},
                            ]),
                        ],
                        "documents": ["snapshot:stable:1", "target:svc-a:1"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_TARGET_PATH_MISMATCH"},
                },
            ],
        }
    )

    # ---------------------------------------------------------------- 9
    cases.append(
        {
            "name": "09-reject-expired-exact",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "snapshot expires exactly at trusted_time",
                    "kind": "update",
                    "package_name": "pkg-09",
                    "trusted_time": 5000,
                    "request_id": "req-09",
                    "build": {
                        "roots": [],
                        "targets": [
                            target_spec("svc-a", 1, root_version=1, snapshot_version=1,
                                        payload="text:x", path="app/services/svc-a.bin"),
                        ],
                        "snapshots": [
                            snapshot_spec(1, root_version=1, entries=[{"target": "svc-a:1"}],
                                          issued_at=1000, expires_at=5000),
                        ],
                        "documents": ["snapshot:stable:1", "target:svc-a:1"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_SNAPSHOT_EXPIRED"},
                },
            ],
        }
    )

    # ---------------------------------------------------------------- 10
    cases.append(
        {
            "name": "10-reject-root-role-duplicate-signer",
            "tenant": tenant_spec(["root-alice", "root-bob", "root-carol", "root-dave",
                                   "snap-eve", "snap-frank", "tgt-heidi", "tgt-ivan"]),
            "bootstrap": {"root": root_v1(), "trusted_time": 1000},
            "steps": [
                {
                    "label": "alice+carol sign as old quorum (only 2 distinct holders) is fine, but",
                    "kind": "update",
                    "package_name": "pkg-10",
                    "trusted_time": 1100,
                    "request_id": "req-10",
                    "build": {
                        "roots": [
                            {
                                "version": 2,
                                "issued_at": 1000,
                                "expires_at": 9200,
                                "root": {"holders": ["root-alice", "root-bob", "root-carol"], "threshold": 2},
                                "snapshot": dict(SNAP_ROLE),
                                "target": dict(TGT_ROLE),
                                "sign": [
                                    # both signatures from alice's single key -> one holder only
                                    {"holder": "root-alice", "key": "alice-k1", "gen": 1},
                                    {"holder": "root-alice", "key": "alice-k1", "gen": 3},
                                ],
                            }
                        ],
                        "targets": [],
                        "snapshots": [],
                        "documents": ["root:2"],
                    },
                    "expect": {"status": "rejected", "error_code": "E_ROOT_OLD_THRESHOLD"},
                },
            ],
        }
    )

    return {"format": "simupd-cases/1", "cases": cases}


def main() -> int:
    target = os.path.join(REPO_ROOT, "cases.json")
    payload = build_cases()
    with open(target, "wb") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"))
        handle.write(b"\n")
    print(f"wrote {target} ({len(payload['cases'])} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
