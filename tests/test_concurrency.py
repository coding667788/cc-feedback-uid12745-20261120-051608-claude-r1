"""Concurrency, crash fences, read-only views and replay.

The crash tests deliberately kill a *child* process with ``os._exit`` at a
sync point, then reopen the same database in the parent.  That is the only
honest way to prove the publish is a single atomic unit.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import unittest

from solution.errors import UpdateError
from solution.state import Store
from solution.updater import Updater

from tests.support import (
    REPO_ROOT,
    TENANT,
    TenantHarness,
    root_v2,
    snapshot_spec,
    target_spec,
)


class ConcurrencyTests(TenantHarness):
    def _prepare_package(self, name, *, channel_version=1, target_version=1, payload=b"payload-v1"):
        target = self.session.build_target(
            target_spec("svc-a", target_version, payload=payload.decode("utf-8"), snapshot_version=channel_version)
        )
        snap = self.session.build_snapshot(
            snapshot_spec(
                channel_version,
                [
                    {
                        "target_id": target["target_id"],
                        "version": target["version"],
                        "purpose": target["purpose"],
                        "repo_tag": target["repo_tag"],
                        "path": target["path"],
                        "manifest_digest": None,
                    }
                ],
            ),
            [],
        )
        # rebuild the entry with the true digest (the builder's make_entry does it)
        entries = [self.session.make_entry(target)]
        snap = self.session.build_snapshot(snapshot_spec(channel_version, entries), entries)
        package_dir = self.write(name, [snap, target], {target["path"]: payload})
        return package_dir, target, snap

    def test_pre_state_is_one_consistent_read(self):
        """The root used for verification and the watermarks that get rechecked
        must come from the same database snapshot."""
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("pre", [snap, target], {target["path"]: b"svc-a-v1"})
        plan = self.updater.prepare(TENANT, package_dir, "pre-1", 1300)
        pre = plan.pre
        self.assertEqual(pre.root_version, plan.root_before["version"])
        self.assertEqual(pre.root_digest, self._doc_digest(plan.root_before))
        self.assertEqual(pre.root_doc, plan.root_before)
        # And the pre-state is re-derived inside the transaction, so a writer
        # that commits after prepare cannot be mistaken for the prepared state.
        self.assertEqual(pre.channel_versions, self.store.channel_versions(TENANT))

    @staticmethod
    def _doc_digest(doc):
        from solution.docs import doc_digest

        return doc_digest(doc)

    def test_two_writers_one_wins_and_one_conflicts(self):
        pkg_a, _, _ = self._prepare_package("conc-a")

        # Both writers verify against the *same* pre-state, outside any txn.
        plan_a = self.updater.prepare(TENANT, pkg_a, "req-a", 1300)
        plan_b = Updater(Store(self.db_path)).prepare(TENANT, pkg_a, "req-b", 1300)

        # A publishes first.
        outcome_a = self.updater.publish(plan_a)
        self.assertEqual(outcome_a["status"], "committed")

        # B prepared against the old floor and must now conflict.
        with self.assertRaises(UpdateError) as ctx:
            self.updater.publish(plan_b)
        self.assertEqual(ctx.exception.code, "E_CONCURRENCY_CONFLICT")

        # The database still reflects exactly A.
        self.assertEqual(self.store.channel_versions(TENANT), {"stable": 1})
        self.assertEqual(self.store.target_floors(TENANT), {"svc-a": 1})
        self.store.audit(TENANT)

    def test_other_writer_rotated_root_first(self):
        # Writer B's package only rotates the root.
        v2 = self.session.build_root(root_v2())
        package_b = self.write("root-only", [v2], {})
        plan_b = self.updater.prepare(TENANT, package_b, "req-b", 1300)

        # Writer A publishes a full update that also rotates the root.
        target = self.session.build_target(target_spec("svc-a", 1, root_version=2))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)], root_version=2), []
        )
        package_a = self.write("full", [v2, snap, target], {target["path"]: b"svc-a-v1"})
        plan_a = Updater(Store(self.db_path)).prepare(TENANT, package_a, "req-a", 1300)
        self.updater.publish(plan_a)

        with self.assertRaises(UpdateError) as ctx:
            self.updater.publish(plan_b)
        self.assertEqual(ctx.exception.code, "E_CONCURRENCY_CONFLICT")
        self.assertEqual(ctx.exception.detail["prepared_root"], 1)
        self.assertEqual(ctx.exception.detail["current_root"], 2)

    def test_replay_with_same_request_id_returns_same_receipt(self):
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("replay", [snap, target], {target["path"]: b"svc-a-v1"})
        first = self.updater.publish(self.updater.prepare(TENANT, package_dir, "req-x", 1300))
        second = self.updater.publish(self.updater.prepare(TENANT, package_dir, "req-x", 1300))
        self.assertEqual(first["receipt"]["receipt_digest"], second["receipt"]["receipt_digest"])
        self.assertEqual(second["status"], "replayed")

    def test_reused_request_id_with_different_package_is_rejected(self):
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("replay-a", [snap, target], {target["path"]: b"svc-a-v1"})
        self.updater.publish(self.updater.prepare(TENANT, package_dir, "req-dup", 1300))

        target2 = self.session.build_target(target_spec("svc-b", 1, snapshot_version=2))
        snap2 = self.session.build_snapshot(
            snapshot_spec(2, [self.session.make_entry(target2)]), []
        )
        other_dir = self.write("replay-b", [snap2, target2], {target2["path"]: b"svc-b-v1"})
        plan = self.updater.prepare(TENANT, other_dir, "req-dup", 1400)
        with self.assertRaises(UpdateError) as ctx:
            self.updater.publish(plan)
        self.assertEqual(ctx.exception.code, "E_REQUEST_REPLAY_CONFLICT")

    def test_concurrent_threads_exactly_one_commits(self):
        """Many threads prepare the same package; one commits, the rest conflict."""
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("threads", [snap, target], {target["path"]: b"svc-a-v1"})
        plans = [
            Updater(Store(self.db_path)).prepare(TENANT, package_dir, f"req-t{i}", 1300)
            for i in range(6)
        ]
        results: list = []
        barrier = threading.Barrier(len(plans))

        def worker(plan):
            barrier.wait()
            try:
                results.append(("ok", self.updater.publish(plan)["status"]))
            except UpdateError as exc:
                results.append(("err", exc.code))

        threads = [threading.Thread(target=worker, args=(plan,)) for plan in plans]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        statuses = [value for kind, value in results if kind == "ok"]
        errors = [value for kind, value in results if kind == "err"]
        self.assertEqual(len(statuses), 1, results)
        self.assertTrue(all(code in ("E_CONCURRENCY_CONFLICT", "E_STORE_BUSY") for code in errors), errors)
        self.assertEqual(self.store.target_floors(TENANT), {"svc-a": 1})


class ReadOnlyViewTests(TenantHarness):
    def test_reader_on_old_snapshot_does_not_see_new_commit(self):
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("ro1", [snap, target], {target["path"]: b"svc-a-v1"})
        first = self.updater.publish(self.updater.prepare(TENANT, package_dir, "ro-1", 1300))
        digest_v1 = first["receipt"]["channels"]["stable"]["snapshot_digest"]

        # Second publish happens while we hold a reader-side reference.
        target2 = self.session.build_target(target_spec("svc-a", 2, payload="svc-a-v2", snapshot_version=2))
        snap2 = self.session.build_snapshot(
            snapshot_spec(2, [self.session.make_entry(target2)]), []
        )
        package_dir2 = self.write("ro2", [snap2, target2], {target2["path"]: b"svc-a-v2"})
        self.updater.publish(self.updater.prepare(TENANT, package_dir2, "ro-2", 1400))

        # Fixed-version reads still return the old, verified snapshot.
        old = self.store.read_channel(TENANT, "stable", 1)
        new = self.store.read_channel(TENANT, "stable", 2)
        self.assertEqual(old["snapshot_digest"], digest_v1)
        self.assertEqual(new["version"], 2)
        self.assertNotEqual(old["snapshot_digest"], new["snapshot_digest"])
        # And the pinned root version for the old snapshot is intact.
        self.assertEqual(old["snapshot"]["root_version"], 1)

    def test_read_connection_is_read_only(self):
        self.store.install_anchor(TENANT, self.bootstrap_root, digest_json_for(self.bootstrap_root), 1000)
        conn = self.store._ro_conn()
        try:
            with self.assertRaises(Exception):
                conn.execute("INSERT INTO tenants(tenant, trusted_time, root_version, root_digest, updated_at) VALUES ('x',0,0,'x',0)")
        finally:
            conn.close()

    def test_database_rejects_mutating_published_rows(self):
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        self.commit("immutable", [snap, target], {target["path"]: b"svc-a-v1"},
                    trusted_time=1300, request_id="imm")
        conn = self.store._conn()
        for statement in (
            "UPDATE roots SET digest = 'x'",
            "UPDATE snapshots SET digest = 'x'",
            "UPDATE target_history SET version = 99",
            "UPDATE blobs SET content = 'y'",
            "UPDATE signature_claims SET nonce = 'z'",
        ):
            with self.assertRaises(Exception, msg=statement):
                conn.execute(statement)

    def test_pointer_cannot_reference_missing_snapshot(self):
        conn = self.store._conn()
        with self.assertRaises(Exception):
            conn.execute(
                "INSERT INTO channels(tenant, channel, version, snapshot_digest) VALUES (?,?,?,?)",
                (TENANT, "ghost", 1, "0" * 64),
            )


def digest_json_for(doc: dict) -> str:
    from solution.docs import doc_digest

    return doc_digest(doc)


class CrashFenceTests(TenantHarness):
    """Terminate a child process at a sync point and verify the restart."""

    def _write_worker(self, name: str) -> str:
        script = textwrap.dedent(
            f"""
            import json, os, sys
            sys.path.insert(0, {REPO_ROOT!r})
            from solution.cases import load_cases, run_cases

            doc = json.load(open(sys.argv[1], "rb"))
            work_root = sys.argv[2]
            result = run_cases(doc, work_root)
            print(json.dumps(result["summary"]))
            """
        )
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        return path

    def test_process_killed_before_commit_leaves_no_trace(self):
        # Build the package in the parent so the child only verifies/publishes.
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("crash-before", [snap, target], {target["path"]: b"svc-a-v1"})

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import sys
                    sys.path.insert(0, {REPO_ROOT!r})
                    from solution.builder import Session
                    from solution.cases import CaseWorkspace
                    from solution.updater import Updater
                    from solution.docs import doc_digest
                    ws = CaseWorkspace("child", {self.tmp!r})
                    ws.domain = None
                    up = Updater(ws.store)
                    plan = up.prepare({TENANT!r}, {package_dir!r}, "req-crash", 1300)
                    up.publish(plan)
                    """
                ),
            ],
            env={**os.environ, "SIMUPD_SYNC_POINT": "before_publish_commit"},
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(child.returncode, 97, child.stderr.decode("utf-8", "replace"))

        # Restart: fresh connection to the same file, nothing committed.
        store = Store(self.db_path)
        self.addCleanup(store.close)
        self.assertEqual(store.channel_versions(TENANT), {})
        self.assertEqual(store.target_floors(TENANT), {})
        self.assertEqual(store.audit(TENANT)["root_version"], 1)
        self.assertIsNone(store.receipt(TENANT, "req-crash"))

        # The same package can be published cleanly afterwards.
        outcome = self.updater.publish(
            self.updater.prepare(TENANT, package_dir, "req-crash", 1300)
        )
        self.assertEqual(outcome["status"], "committed")
        self.assertEqual(self.store.channel_versions(TENANT), {"stable": 1})

    def test_process_killed_after_commit_before_return_keeps_state(self):
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("crash-after", [snap, target], {target["path"]: b"svc-a-v1"})

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import sys
                    sys.path.insert(0, {REPO_ROOT!r})
                    from solution.cases import CaseWorkspace
                    from solution.updater import Updater
                    ws = CaseWorkspace("child2", {self.tmp!r})
                    up = Updater(ws.store)
                    plan = up.prepare({TENANT!r}, {package_dir!r}, "req-crash2", 1300)
                    up.publish(plan)
                    """
                ),
            ],
            env={**os.environ, "SIMUPD_SYNC_POINT": "after_commit_before_return"},
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(child.returncode, 97, child.stderr.decode("utf-8", "replace"))

        store = Store(self.db_path)
        self.addCleanup(store.close)
        audit = store.audit(TENANT)
        self.assertTrue(audit["ok"])
        self.assertEqual(audit["channel_versions"], {"stable": 1})
        self.assertEqual(audit["target_floors"], {"svc-a": 1})

        # Replaying the identical request must return the stored receipt, not
        # a second commit - and must not raise.
        plan = Updater(store).prepare(TENANT, package_dir, "req-crash2", 1300)
        again = Updater(store).publish(plan)
        self.assertEqual(again["status"], "replayed")
        self.assertEqual(again["receipt"]["request_id"], "req-crash2")

    def test_after_crash_the_watermark_is_not_lower_than_before(self):
        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [self.session.make_entry(target)]), []
        )
        package_dir = self.write("wm", [snap, target], {target["path"]: b"svc-a-v1"})
        self.updater.publish(self.updater.prepare(TENANT, package_dir, "wm-1", 1500))

        # A second package dies before commit.
        target2 = self.session.build_target(target_spec("svc-a", 2, payload="svc-a-v2", snapshot_version=2))
        snap2 = self.session.build_snapshot(
            snapshot_spec(2, [self.session.make_entry(target2)]), []
        )
        package_dir2 = self.write("wm2", [snap2, target2], {target2["path"]: b"svc-a-v2"})
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import sys
                    sys.path.insert(0, {REPO_ROOT!r})
                    from solution.cases import CaseWorkspace
                    from solution.updater import Updater
                    ws = CaseWorkspace("child3", {self.tmp!r})
                    up = Updater(ws.store)
                    up.publish(up.prepare({TENANT!r}, {package_dir2!r}, "wm-2", 1600))
                    """
                ),
            ],
            env={**os.environ, "SIMUPD_SYNC_POINT": "before_publish_commit"},
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(child.returncode, 97)

        store = Store(self.db_path)
        self.addCleanup(store.close)
        audit = store.audit(TENANT)
        self.assertEqual(audit["channel_versions"]["stable"], 1)
        self.assertEqual(audit["target_floors"]["svc-a"], 1)
        self.assertEqual(audit["trusted_time"], 1500)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
