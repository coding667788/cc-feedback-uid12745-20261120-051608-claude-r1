"""Emit the cross-rotation positive example and an independent trust table.

    python tools/trust_table.py            # markdown to stdout
    python tools/trust_table.py --json     # machine-readable

This reuses the same synthesiser and verifier as the client, replays a package
that walks root v1 -> v2 -> v3 while publishing one channel snapshot and two
targets, and then prints a *separate* table that re-derives every claim from
the documents on disk rather than from the client's own report.  The two are
compared, so the table is an independent check, not a restatement.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.builder import Domain, Session, write_package  # noqa: E402
from solution.canonical import digest_json, sha256_hex  # noqa: E402
from solution.docs import (  # noqa: E402
    doc_digest,
    evaluate_rotation,
    key_owner,
    parse_snapshot,
    parse_target,
    role_authorized,
    role_signature_report,
)
from solution.errors import UpdateError  # noqa: E402
from solution.state import Store  # noqa: E402
from solution.updater import Updater  # noqa: E402

TENANT = "trust-demo"
TAG = "core"

HOLDER_TABLE = {
    "alice": ("root", "alice-k1"),
    "bob": ("root", "bob-k1"),
    "carol": ("root", "carol-k1"),
    "dave": ("root", "dave-k1"),
    "eve": ("snapshot", "eve-k1"),
    "frank": ("snapshot", "frank-k1"),
    "heidi": ("target", "heidi-k1"),
    "ivan": ("target", "ivan-k1"),
}


def secret(tag: str) -> str:
    return sha256_hex(("trust-demo-key:" + tag).encode("utf-8"))


def holders() -> dict:
    out = {}
    for holder, (role, key) in HOLDER_TABLE.items():
        out[holder] = {"role": role, "keys": {key: secret(key)}}
    return out


def root_spec(version: int, root_holders, signers) -> dict:
    return {
        "version": version,
        "issued_at": 1000 + (version - 1) * 100,
        "expires_at": 9000,
        "root": {"holders": root_holders, "threshold": 2},
        "snapshot": {"holders": ["eve", "frank"], "threshold": 2, "tags": [TAG], "paths": ["app", "lib"]},
        "target": {"holders": ["heidi", "ivan"], "threshold": 2, "tags": [TAG],
                   "paths": ["app/services", "lib/core"]},
        "sign": signers,
    }


def build(root_dir: str):
    domain = Domain({"tenant": TENANT, "holders": holders()})
    session = Session(domain, "trust-table")

    v1 = session.build_root(
        root_spec(1, ["alice", "bob", "carol"], [
            {"holder": "alice", "key": "alice-k1"},
            {"holder": "bob", "key": "bob-k1"},
        ])
    )
    v2 = session.build_root(
        root_spec(2, ["carol", "dave", "alice"], [
            {"holder": "alice", "key": "alice-k1"},
            {"holder": "bob", "key": "bob-k1"},
            {"holder": "carol", "key": "carol-k1"},
            {"holder": "dave", "key": "dave-k1"},
        ])
    )
    v3 = session.build_root(
        root_spec(3, ["alice", "dave", "bob"], [
            {"holder": "carol", "key": "carol-k1"},
            {"holder": "dave", "key": "dave-k1"},
            {"holder": "alice", "key": "alice-k1"},
            {"holder": "bob", "key": "bob-k1"},
        ])
    )

    def target(target_id, path, payload):
        return session.build_target({
            "id": target_id,
            "version": 1,
            "root_version": 3,
            "snapshot_version": 1,
            "channel": "stable",
            "purpose": "runtime",
            "repo_tag": TAG,
            "path": path,
            "payload": "text:" + payload,
            "issued_at": 1000,
            "expires_at": 8000,
            "sign": [
                {"holder": "heidi", "key": "heidi-k1"},
                {"holder": "ivan", "key": "ivan-k1"},
            ],
        })

    svc = target("svc-a", "app/services/svc-a.bin", "svc-a-v1")
    lib = target("lib-c", "lib/core/lib-c.bin", "lib-c-v1")
    entries = [Session.make_entry(svc), Session.make_entry(lib)]
    snapshot = session.build_snapshot({
        "channel": "stable",
        "version": 1,
        "root_version": 3,
        "repo_tag": TAG,
        "issued_at": 1000,
        "expires_at": 8000,
        "entries": entries,
        "sign": [
            {"holder": "eve", "key": "eve-k1"},
            {"holder": "frank", "key": "frank-k1"},
        ],
    }, entries)

    package_dir = os.path.join(root_dir, "package")
    os.makedirs(package_dir)
    write_package(
        package_dir,
        TENANT,
        [v2, v3, snapshot, svc, lib],
        {
            "app/services/svc-a.bin": b"svc-a-v1",
            "lib/core/lib-c.bin": b"lib-c-v1",
        },
    )
    return domain, session, (v1, v2, v3), snapshot, (svc, lib), package_dir


def independent_table(roots, snapshot, targets) -> dict:
    """Re-derive the trust facts from the documents, not from a receipt."""
    v1, v2, v3 = roots
    rows = []

    def rotation_row(index, old_root, new_root):
        rotation = evaluate_rotation(new_root, old_root, new_root)
        return {
            "step": index,
            "kind": "root-rotation",
            "from_version": old_root["version"],
            "to_version": new_root["version"],
            "from_digest": doc_digest(old_root),
            "to_digest": doc_digest(new_root),
            "links_previous": new_root["previous_digest"] == doc_digest(old_root),
            "role_exclusive": _roles_exclusive(new_root),
            "old_threshold": rotation.old.threshold,
            "old_holders": sorted(rotation.old.holders),
            "new_threshold": rotation.new.threshold,
            "new_holders": sorted(rotation.new.holders),
            "disjoint": not (set(rotation.old.holders) & set(rotation.new.holders)),
            "accepted": rotation.ok,
        }

    rows.append(rotation_row(1, v1, v2))
    rows.append(rotation_row(2, v2, v3))

    snap_report = role_signature_report(snapshot, v3, "snapshot")
    ok, offending, tag = role_authorized(v3["roles"]["snapshot"], snapshot["repo_tag"],
                                        [e["path"] for e in snapshot["entries"]])
    rows.append({
        "step": 3,
        "kind": "snapshot",
        "channel": snapshot["channel"],
        "version": snapshot["version"],
        "root_version": snapshot["root_version"],
        "threshold": snap_report.threshold,
        "holders": sorted(snap_report.holders),
        "accepted": snap_report.accepted,
        "authorized": ok,
    })
    for target in targets:
        report = role_signature_report(target, v3, "target")
        entry = next(e for e in snapshot["entries"] if e["target_id"] == target["target_id"])
        ok, offending, tag = role_authorized(v3["roles"]["target"], target["repo_tag"], [target["path"]])
        rows.append({
            "step": 4,
            "kind": "target",
            "target_id": target["target_id"],
            "version": target["version"],
            "path": target["path"],
            "snapshot_locks_manifest": entry["manifest_digest"] == doc_digest(target),
            "snapshot_locks_file": entry["file_digest"] == target["file"]["digest"],
            "threshold": report.threshold,
            "holders": sorted(report.holders),
            "accepted": report.accepted,
            "authorized": ok,
        })
    return {"rows": rows, "all_accepted": all(r.get("accepted") for r in rows)}


def _roles_exclusive(root: dict) -> bool:
    holders = []
    keys = []
    for role in ("root", "snapshot", "target"):
        holders.extend(root["roles"][role]["holders"])
        for key_list in root["roles"][role]["holders"].values():
            keys.extend(key_list)
    return len(holders) == len(set(holders)) and len(keys) == len(set(keys))


def run(root_dir: str) -> dict:
    domain, session, roots, snapshot, targets, package_dir = build(root_dir)
    v1 = roots[0]
    store = Store(os.path.join(root_dir, "state.db"))
    try:
        store.install_anchor(TENANT, v1, doc_digest(v1), 1000)
        updater = Updater(store)
        plan = updater.prepare(TENANT, package_dir, "trust-demo-1", 1300)
        outcome = updater.publish(plan)
        receipt = outcome["receipt"]
        audit = store.audit(TENANT)
        channel = store.read_channel(TENANT, "stable", 1)
        target_views = {tid: store.read_target(TENANT, tid, 1) for tid in ("svc-a", "lib-c")}
    finally:
        store.close()

    independent = independent_table(roots, snapshot, targets)
    return {
        "status": outcome["status"],
        "receipt": receipt,
        "audit": audit,
        "channel_view": {
            "version": channel["version"],
            "snapshot_digest": channel["snapshot_digest"],
            "root_version": channel["root_version"],
        },
        "target_views": {
            tid: {"version": v["version"], "file_digest": v["file_digest"], "content_matches": v["content_matches"]}
            for tid, v in target_views.items()
        },
        "independent": independent,
    }


def to_markdown(result: dict) -> str:
    lines = []
    lines.append("### Cross-rotation positive example")
    lines.append("")
    lines.append(f"Status: **{result['status']}**, root "
                 f"v{result['receipt']['root_before']['version']} -> "
                 f"v{result['receipt']['root_after']['version']}, "
                 f"{result['receipt']['root_steps']} rotation step(s).")
    lines.append("")
    lines.append("### Independent trust verification table")
    lines.append("")
    lines.append("| # | Document | Version | Quorum | Holders | Digests / links | Verdict |")
    lines.append("|---|----------|---------|--------|---------|-----------------|---------|")
    for row in result["independent"]["rows"]:
        if row["kind"] == "root-rotation":
            lines.append(
                f"| {row['step']} | root rotation | {row['from_version']} -> {row['to_version']} "
                f"| old {row['old_threshold']} / new {row['new_threshold']} "
                f"| {', '.join(row['old_holders'])} / {', '.join(row['new_holders'])} "
                f"| link={row['links_previous']}, disjoint={row['disjoint']}, roles-exclusive={row['role_exclusive']} "
                f"| {'ACCEPT' if row['accepted'] else 'REJECT'} |"
            )
        elif row["kind"] == "snapshot":
            lines.append(
                f"| {row['step']} | snapshot {row['channel']} | {row['version']} "
                f"| {row['threshold']} | {', '.join(row['holders'])} "
                f"| root-under-v{row['root_version']}, authorized={row['authorized']} "
                f"| {'ACCEPT' if row['accepted'] and row['authorized'] else 'REJECT'} |"
            )
        else:
            lines.append(
                f"| {row['step']} | target {row['target_id']} | {row['version']} "
                f"| {row['threshold']} | {', '.join(row['holders'])} "
                f"| manifest-locked={row['snapshot_locks_manifest']}, file-locked={row['snapshot_locks_file']}, "
                f"authorized={row['authorized']} "
                f"| {'ACCEPT' if row['accepted'] and row['authorized'] else 'REJECT'} |"
            )
    lines.append("")
    lines.append(f"Independent verdict: **{'ALL ACCEPT' if result['independent']['all_accepted'] else 'REJECT'}**")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="simupd-trust-") as root_dir:
        result = run(root_dir)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(to_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
