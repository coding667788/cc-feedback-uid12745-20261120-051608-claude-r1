"""Pipeline tests: what the updater accepts, what it refuses, and why."""

from __future__ import annotations

import os
import unittest

from solution.builder import Session
from solution.errors import UpdateError

from tests.support import (
    TENANT,
    TenantHarness,
    root_v1,
    root_v2,
    snapshot_spec,
    target_spec,
)


class HappyPathTests(TenantHarness):
    def test_rotates_twice_and_publishes_two_targets(self):
        v2 = self.session.build_root(root_v2())
        target_a = self.build_target("svc-a", 1, root_version=2)
        target_b = self.session.build_target(
            target_spec("lib-c", 1, root_version=2, path="lib/core/lib-c.bin", payload="text:lib-c-v1")
        )
        snap = self.build_snapshot(1, ["svc-a:1", "lib-c:1"], root_version=2)
        files = {"app/services/svc-a.bin": b"svc-a-v1", "lib/core/lib-c.bin": b"lib-c-v1"}
        outcome, plan = self.commit(
            "happy", [v2, snap, target_a, target_b], files, trusted_time=1300, request_id="r1"
        )
        self.assertEqual(outcome["status"], "committed")
        receipt = outcome["receipt"]
        self.assertEqual(receipt["root_after"]["version"], 2)
        self.assertEqual(receipt["channels"]["stable"]["version"], 1)
        self.assertEqual(set(receipt["targets"]), {"svc-a", "lib-c"})
        # 1 root step + 1 snapshot + 2 targets
        self.assertEqual(len(receipt["trust_table"]), 4)

    def test_receipt_records_both_quorums(self):
        v2 = self.session.build_root(root_v2())
        target = self.build_target("svc-a", 1, root_version=2)
        snap = self.build_snapshot(1, ["svc-a:1"], root_version=2)
        outcome, _ = self.commit(
            "quorum", [v2, snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"}, trusted_time=1300, request_id="r2",
        )
        root_row = outcome["receipt"]["trust_table"][0]
        self.assertEqual(root_row["role"], "root")
        self.assertEqual(root_row["from_version"], 1)
        self.assertEqual(root_row["to_version"], 2)
        self.assertEqual(sorted(root_row["old_root_quorum"]["holders"]), ["root-a", "root-b"])
        self.assertEqual(sorted(root_row["new_root_quorum"]["holders"]), ["root-c", "root-d"])

    def test_read_only_view_pins_the_committed_snapshot(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        outcome, _ = self.commit(
            "ro", [snap, target], {"app/services/svc-a.bin": b"svc-a-v1"},
            trusted_time=1300, request_id="r3",
        )
        digest = outcome["receipt"]["channels"]["stable"]["snapshot_digest"]
        view = self.store.read_channel(self.tenant, "stable", 1)
        self.assertEqual(view["snapshot_digest"], digest)
        self.assertEqual(view["version"], 1)
        second = self.store.read_channel(self.tenant, "stable", 1)
        self.assertEqual(view["snapshot"], second["snapshot"])

    @property
    def tenant(self):
        from tests.support import TENANT

        return TENANT


class RefusalTests(TenantHarness):
    def _expect(self, code, docs, files, trusted_time=1300, request_id="r"):
        package_dir = self.write("pkg", docs, files)
        with self.assertRaises(UpdateError) as ctx:
            plan = self.updater.prepare(TENANT, package_dir, request_id, trusted_time)
            self.updater.publish(plan)
        self.assertEqual(ctx.exception.code, code, ctx.exception.message)
        return ctx.exception

    def test_root_rollback_refused(self):
        # Confirm v2 first.
        v2 = self.session.build_root(root_v2())
        target = self.build_target("svc-a", 1, root_version=2)
        snap = self.build_snapshot(1, ["svc-a:1"], root_version=2)
        self.commit("to-v2", [v2, snap, target], {"app/services/svc-a.bin": b"svc-a-v1"},
                    trusted_time=1300, request_id="r-a")

        # A fresh package offers v1 again.
        old_session = Session(self.domain, "old")
        old_root = old_session.build_root(
            {
                "version": 1, "issued_at": 1000, "expires_at": 9000,
                "root": {"holders": ["root-a", "root-b", "root-c"], "threshold": 2},
                "snapshot": {"holders": ["snap-1", "snap-2"], "threshold": 2,
                             "tags": ["core"], "paths": ["app", "lib"]},
                "target": {"holders": ["tgt-1", "tgt-2"], "threshold": 2,
                           "tags": ["core"], "paths": ["app/services", "lib/core"]},
                "sign": [{"holder": "root-a", "key": "a1"}, {"holder": "root-b", "key": "b1"}],
            }
        )
        self._expect("E_ROOT_ROLLBACK", [old_root], {})

    def test_version_skip_refused(self):
        v2 = self.session.build_root(root_v2())
        v3 = self.session.build_root(
            {
                "version": 3, "issued_at": 1200, "expires_at": 9400,
                "root": {"holders": ["root-a", "root-b", "root-c"], "threshold": 2},
                "snapshot": {"holders": ["snap-1", "snap-2"], "threshold": 2,
                             "tags": ["core"], "paths": ["app", "lib"]},
                "target": {"holders": ["tgt-1", "tgt-2"], "threshold": 2,
                           "tags": ["core"], "paths": ["app/services", "lib/core"]},
                "sign": [
                    {"holder": "root-c", "key": "c1"}, {"holder": "root-d", "key": "d1"},
                    {"holder": "root-a", "key": "a1"}, {"holder": "root-b", "key": "b1"},
                ],
            }
        )
        self._expect("E_ROOT_VERSION_SKIP", [v3], {})

    def test_snapshot_from_another_root_refused(self):
        v2 = self.session.build_root(root_v2())
        target = self.build_target("svc-a", 1, root_version=2)
        snap = self.session.build_snapshot(
            snapshot_spec(1, [Session.make_entry(target)], root_version=1), []
        )
        self._expect(
            "E_SNAPSHOT_NOT_CONFIRMED_ROOT",
            [v2, snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
        )

    def test_time_rollback_refused(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        self.commit("t1", [snap, target], {"app/services/svc-a.bin": b"svc-a-v1"},
                    trusted_time=5000, request_id="r-t1")
        package_dir = self.write("pkg-time", [], {})
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(TENANT, package_dir, "r-t2", 4999)
        self.assertEqual(ctx.exception.code, "E_TIME_ROLLBACK")

    def test_target_path_outside_role_prefix_refused(self):
        target = self.build_target("svc-a", 1, path="app/other/svc-a.bin")
        snap = self.build_snapshot(1, ["svc-a:1"])
        self._expect(
            "E_TARGET_PATH_UNAUTHORIZED",
            [snap, target],
            {"app/other/svc-a.bin": b"svc-a-v1"},
        )

    def test_target_path_prefix_is_not_string_prefix(self):
        target = self.build_target("svc-a", 1, path="app/servicesevil/x.bin")
        snap = self.build_snapshot(1, ["svc-a:1"])
        self._expect("E_TARGET_PATH_UNAUTHORIZED", [snap, target], {"app/servicesevil/x.bin": b"x"})

    def test_file_digest_mismatch_refused(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        self._expect(
            "E_FILE_DIGEST_MISMATCH",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1-tampered"},
        )

    def test_missing_payload_file_refused(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        self._expect("E_FILE_MISSING", [snap, target], {})

    def test_expiry_is_exclusive(self):
        target = self.build_target("svc-a", 1, expires_at=5000)
        snap = self.build_snapshot(1, ["svc-a:1"], expires_at=9000)
        self._expect(
            "E_TARGET_EXPIRED",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
            trusted_time=5000,
        )

    def test_valid_one_tick_before_expiry(self):
        target = self.build_target("svc-a", 1, expires_at=5000)
        snap = self.build_snapshot(1, ["svc-a:1"])
        outcome, _ = self.commit(
            "tick", [snap, target], {"app/services/svc-a.bin": b"svc-a-v1"},
            trusted_time=4999, request_id="r-tick",
        )
        self.assertEqual(outcome["status"], "committed")

    def test_not_yet_valid_refused(self):
        target = self.build_target("svc-a", 1, issued_at=6000)
        snap = self.build_snapshot(1, ["svc-a:1"], issued_at=6000)
        self._expect(
            "E_SNAPSHOT_NOT_YET_VALID",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
            trusted_time=5000,
        )

    def test_target_not_yet_valid_refused(self):
        target = self.build_target("svc-a", 1, issued_at=6000)
        snap = self.build_snapshot(1, ["svc-a:1"], issued_at=4000)
        self._expect(
            "E_TARGET_NOT_YET_VALID",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
            trusted_time=5000,
        )

    def test_snapshot_threshold_not_met(self):
        target = self.build_target("svc-a", 1)
        snap = self.session.build_snapshot(
            snapshot_spec(
                1, [Session.make_entry(target)],
                sign=[{"holder": "snap-1", "key": "s1"}],
            ),
            [],
        )
        self._expect(
            "E_SNAPSHOT_THRESHOLD",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
        )

    def test_snapshot_role_path_unauthorized(self):
        target = self.build_target("svc-a", 1)
        # Validly signed snapshot that lists an entry outside the snapshot
        # role's path prefixes: the signature is good, the authorization is not.
        snap = self.build_snapshot(
            1,
            ["svc-a:1"],
            tamper_before_sign={
                "entries": [
                    {
                        "target_id": "svc-a",
                        "version": 1,
                        "purpose": "runtime",
                        "repo_tag": "core",
                        "path": "vendor/other.bin",
                        "manifest_digest": "a" * 64,
                        "file_digest": "b" * 64,
                    }
                ]
            },
        )
        exc = self._expect(
            "E_SNAPSHOT_UNAUTHORIZED",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
        )
        self.assertEqual(exc.detail["offending_path"], "vendor/other.bin")

    def test_snapshot_tag_unauthorized(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"], repo_tag="extra")
        self._expect(
            "E_SNAPSHOT_UNAUTHORIZED",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
        )

    def test_target_claiming_another_root_is_rejected(self):
        target = self.build_target("svc-a", 1, root_version=3)
        snap = self.build_snapshot(1, ["svc-a:1"])
        exc = self._expect(
            "E_TARGET_NOT_CONFIRMED_ROOT",
            [snap, target],
            {"app/services/svc-a.bin": b"svc-a-v1"},
        )
        self.assertEqual(exc.detail["target_root"], 3)
        self.assertEqual(exc.detail["confirmed_root"], 1)

    def test_confirmed_root_expiry_blocks_new_publications(self):
        """An expired confirmed root must not keep authorising snapshots."""
        expired_root = self.session.build_root(root_v1(expires_at=2000))
        from solution.docs import doc_digest
        from solution.state import Store
        from solution.updater import Updater
        import os as _os

        store = Store(_os.path.join(self.tmp, "expired.db"))
        self.addCleanup(store.close)
        store.install_anchor(TENANT, expired_root, doc_digest(expired_root), 1000)

        target = self.session.build_target(target_spec("svc-a", 1))
        snap = self.session.build_snapshot(
            snapshot_spec(1, [Session.make_entry(target)], expires_at=9000), []
        )
        package_dir = self.write("exp-root", [snap, target], {target["path"]: b"svc-a-v1"})
        updater = Updater(store)
        with self.assertRaises(UpdateError) as ctx:
            updater.prepare(TENANT, package_dir, "exp-1", 5000)
        self.assertEqual(ctx.exception.code, "E_ROOT_EXPIRED")

        # One tick before expiry the same package is fine.
        outcome = updater.publish(updater.prepare(TENANT, package_dir, "exp-2", 1999))
        self.assertEqual(outcome["status"], "committed")

    def test_target_link_must_reference_previous_digest(self):
        v1 = self.build_target("svc-a", 1)
        snap1 = self.build_snapshot(1, ["svc-a:1"])
        self.commit("link1", [snap1, v1], {"app/services/svc-a.bin": b"svc-a-v1"},
                    trusted_time=1200, request_id="r-l1")

        # Signed over content whose predecessor digest is wrong: the snapshot
        # locks this exact document, so only the chain check can catch it.
        v2 = self.build_target(
            "svc-a", 2, snapshot_version=2, tamper_before_sign={"previous_digest": "9" * 64}
        )
        snap2 = self.build_snapshot(2, ["svc-a:2"])
        exc = self._expect(
            "E_MANIFEST_VERSION_ROLLBACK",
            [snap2, v2],
            {"app/services/svc-a.bin": b"svc-a-v2"},
            trusted_time=1300,
        )
        self.assertEqual(exc.detail["floor"], 1)


class DualMirrorTests(TenantHarness):
    def test_missing_file_in_one_mirror(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        with self.assertRaises(UpdateError) as ctx:
            self.write(
                "divergent",
                [snap, target],
                {"app/services/svc-a.bin": b"svc-a-v1"},
                omit_from_mirror={"mirror-b": ["app/services/svc-a.bin"]},
            )
            self.updater.prepare(TENANT, os.path.join(self.package_root, "divergent"), "r", 1300)
        self.assertEqual(ctx.exception.code, "E_MIRROR_MISSING")

    def test_two_mirrors_disagree(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        with self.assertRaises(UpdateError) as ctx:
            self.write(
                "divergent2",
                [snap, target],
                {"app/services/svc-a.bin": b"svc-a-v1"},
                mirror_override={"mirror-b": {"app/services/svc-a.bin": b"svc-a-other"}},
            )
            self.updater.prepare(TENANT, os.path.join(self.package_root, "divergent2"), "r", 1300)
        self.assertEqual(ctx.exception.code, "E_MIRROR_DIVERGENCE")
        self.assertIn("digest_by_mirror", ctx.exception.detail)

    def test_missing_mirror_directory(self):
        package_dir = os.path.join(self.package_root, "onemirror")
        os.makedirs(package_dir, exist_ok=True)
        os.makedirs(os.path.join(package_dir, "mirror-a"), exist_ok=True)
        with open(os.path.join(package_dir, "index.json"), "wb") as handle:
            handle.write(
                b'{"format":"simupd-package/1","tenant":"tenant-test",'
                b'"mirrors":["mirror-a","mirror-b"],"documents":["roots/root-0001.json"],"files":[]}'
            )
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(TENANT, package_dir, "r", 1300)
        self.assertEqual(ctx.exception.code, "E_MIRROR_MISSING")


class SandboxTests(TenantHarness):
    def test_document_path_cannot_escape(self):
        package_dir = os.path.join(self.package_root, "escape")
        os.makedirs(os.path.join(package_dir, "mirror-a"), exist_ok=True)
        os.makedirs(os.path.join(package_dir, "mirror-b"), exist_ok=True)
        with open(os.path.join(package_dir, "index.json"), "wb") as handle:
            handle.write(
                b'{"format":"simupd-package/1","tenant":"tenant-test",'
                b'"mirrors":["mirror-a","mirror-b"],"documents":["../outside.json"],"files":[]}'
            )
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(TENANT, package_dir, "r", 1300)
        self.assertEqual(ctx.exception.code, "E_PATH_ESCAPE")

    def test_absolute_path_rejected(self):
        from solution.canonical import normalize_repo_path

        for bad in ["/etc/passwd", "C:/windows/system32", "app/../../x", "app//x", "app/./x", "app\\x"]:
            with self.assertRaises(UpdateError, msg=bad):
                normalize_repo_path(bad)

    def test_non_canonical_document_bytes_rejected(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        with self.assertRaises(UpdateError) as ctx:
            self.write(
                "noncanon",
                [snap, target],
                {"app/services/svc-a.bin": b"svc-a-v1"},
                raw_doc_bytes={id(target): b'{"doc_type": "target"}'},
            )
            self.updater.prepare(TENANT, os.path.join(self.package_root, "noncanon"), "r", 1300)
        self.assertEqual(ctx.exception.code, "E_INPUT_INVALID")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
