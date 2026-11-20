"""Regression tests for the tightened re-publication and chaining rules.

Each test here pins a behaviour that a naive implementation gets wrong:
re-offering a version must be a *byte-identical* no-op, a snapshot must chain
onto the channel's previous digest, and a target must resolve its snapshot
against the confirmed root rather than simply "some snapshot exists".
"""

from __future__ import annotations

import unittest

from solution.builder import Session
from solution.docs import doc_digest
from solution.errors import UpdateError

from tests.support import TENANT, TenantHarness, root_v2, snapshot_spec, target_spec


class NoOpRepublishTests(TenantHarness):
    def test_identical_republish_is_a_noop(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        package_dir = self.write("noop-1", [snap, target], {target["path"]: b"svc-a-v1"})
        self.updater.publish(self.updater.prepare(TENANT, package_dir, "n1", 1300))

        # Exactly the same package again, new request id.
        second = self.updater.publish(self.updater.prepare(TENANT, package_dir, "n2", 1300))
        self.assertEqual(second["status"], "committed")
        self.assertEqual(
            second["receipt"]["noops"],
            [
                {"kind": "snapshot", "channel": "stable", "version": 1},
                {"kind": "target", "target_id": "svc-a", "version": 1},
            ],
        )
        # Nothing was written twice.
        self.assertEqual(self.store.target_floors(TENANT), {"svc-a": 1})
        self.store.audit(TENANT)

    def test_same_target_version_with_different_purpose_is_a_conflict(self):
        target = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        package_dir = self.write("conf-1", [snap, target], {target["path"]: b"svc-a-v1"})
        self.updater.publish(self.updater.prepare(TENANT, package_dir, "c1", 1300))

        altsess = Session(self.domain, "alt")
        alt = altsess.build_target(target_spec("svc-a", 1, purpose="docs"))
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(TENANT, self.write("conf-2", [alt], {alt["path"]: b"svc-a-v1"}), "c2", 1400)
        self.assertEqual(ctx.exception.code, "E_MANIFEST_CONFLICT")

    def test_same_snapshot_version_with_different_entries_is_a_conflict(self):
        t1 = self.build_target("svc-a", 1)
        snap = self.build_snapshot(1, ["svc-a:1"])
        package_dir = self.write("snapc-1", [snap, t1], {t1["path"]: b"svc-a-v1"})
        self.updater.publish(self.updater.prepare(TENANT, package_dir, "sc1", 1300))

        # A second target at v1 for a *different* id gives a snapshot whose
        # entries differ while carrying the same version number.
        t2 = self.session.build_target(target_spec("lib-c", 1, path="lib/core/lib-c.bin"))
        alt = Session(self.domain, "snapalt")
        alt_snap = alt.build_snapshot(
            snapshot_spec(1, [Session.make_entry(t2)]), []
        )
        package_dir2 = self.write(
            "snapc-2", [alt_snap, t2], {t2["path"]: b"lib-c-v1"}
        )
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(TENANT, package_dir2, "sc2", 1400)
        self.assertEqual(ctx.exception.code, "E_SNAPSHOT_CONFLICT")


class ChainingTests(TenantHarness):
    def test_snapshot_must_chain_to_previous_digest(self):
        target = self.build_target("svc-a", 1)
        snap1 = self.build_snapshot(1, ["svc-a:1"])
        self.updater.publish(
            self.updater.prepare(TENANT, self.write("ch-1", [snap1, target], {target["path"]: b"svc-a-v1"}), "ch1", 1300)
        )

        target2 = self.build_target("svc-a", 2, snapshot_version=2)
        # Build snapshot v2 from a *different* session so its previous_digest
        # is the zero digest rather than the confirmed v1 digest.
        other = Session(self.domain, "chain-other")
        other.build_target(target_spec("svc-a", 1))
        other.build_target(target_spec("svc-a", 2, snapshot_version=2))
        other.build_snapshot(snapshot_spec(1, []), [])
        snap2 = other.build_snapshot(
            snapshot_spec(2, [Session.make_entry(other.targets[("svc-a", 2)])]), []
        )
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(
                TENANT, self.write("ch-2", [snap2, target2], {target2["path"]: b"svc-a-v2"}), "ch2", 1400
            )
        self.assertEqual(ctx.exception.code, "E_SNAPSHOT_VERSION_ORDER")
        self.assertEqual(ctx.exception.detail["expected_previous"], doc_digest(snap1))

    def test_snapshot_below_watermark_is_a_rollback(self):
        target = self.build_target("svc-a", 1)
        snap1 = self.build_snapshot(1, ["svc-a:1"])
        self.updater.publish(
            self.updater.prepare(TENANT, self.write("wm-1", [snap1, target], {target["path"]: b"svc-a-v1"}), "w1", 1300)
        )

        # A fresh session builds a *different* snapshot v1; version is not
        # below the floor, but it is the current version, so it is a conflict.
        other = Session(self.domain, "below")
        alt_target = other.build_target(target_spec("svc-b", 1, path="app/services/svc-b.bin"))
        alt_snap = other.build_snapshot(snapshot_spec(1, [Session.make_entry(alt_target)]), [])
        with self.assertRaises(UpdateError) as ctx:
            self.updater.prepare(
                TENANT, self.write("wm-2", [alt_snap, alt_target], {alt_target["path"]: b"svc-b-v1"}), "w2", 1400
            )
        self.assertEqual(ctx.exception.code, "E_SNAPSHOT_CONFLICT")


class SignatureReplayTests(TenantHarness):
    def test_snapshot_signature_records_cannot_be_reused(self):
        """A consumed signature record may never count again, even for a
        well-formed, correctly chained successor document."""
        from solution.canonical import canonical_json  # noqa: F401
        from solution.signing import sign

        target = self.build_target("svc-a", 1)
        snap1 = self.build_snapshot(1, ["svc-a:1"])
        self.updater.publish(
            self.updater.prepare(
                TENANT, self.write("sr-1", [snap1, target], {target["path"]: b"svc-a-v1"}), "sr1", 1300
            )
        )

        # Build snapshot v2, chain it correctly, then re-sign it with the
        # *same* nonces snapshot v1 already consumed.
        snap2 = self.session.build_snapshot(
            snapshot_spec(2, [Session.make_entry(target)]), [Session.make_entry(target)]
        )
        snap2["previous_digest"] = doc_digest(snap1)
        snap2["signatures"] = [
            sign(snap2, "s1", 1, self.domain.secret("snap-1", "s1"), snap1["signatures"][0]["nonce"]),
            sign(snap2, "s2", 1, self.domain.secret("snap-2", "s2"), snap1["signatures"][1]["nonce"]),
        ]
        consumed = snap1["signatures"][0]["nonce"]

        package_dir = self.write("sr-2", [snap2, target], {target["path"]: b"svc-a-v1"})
        # Replay is enforced by the table's primary key, i.e. at the commit
        # boundary where the claim would actually be recorded.
        with self.assertRaises(UpdateError) as ctx:
            self.updater.publish(self.updater.prepare(TENANT, package_dir, "sr2", 1400))
        self.assertEqual(ctx.exception.code, "E_SIGNATURE_REPLAY")
        self.assertEqual(ctx.exception.detail["nonce"], consumed)


class CrossRootTargetTests(TenantHarness):
    def test_target_signed_under_old_root_cannot_ride_a_new_snapshot(self):
        """Rotate to v2, then offer a snapshot under v2 and a target that
        references a snapshot version which only exists under v1."""
        v2 = self.session.build_root(root_v2())

        # Snapshot v1 under the *new* root, listing a target that claims it
        # belongs to snapshot version 1 - which will be the new one - so build
        # the target first and let it resolve.
        target = self.build_target("svc-a", 1, root_version=2, snapshot_version=1)
        snap = self.build_snapshot(1, ["svc-a:1"], root_version=2)
        outcome, _ = self.commit(
            "x-root", [v2, snap, target], {target["path"]: b"svc-a-v1"},
            trusted_time=1300, request_id="xr1",
        )
        self.assertEqual(outcome["status"], "committed")
        self.assertEqual(outcome["receipt"]["root_after"]["version"], 2)
        self.assertEqual(outcome["receipt"]["channels"]["stable"]["snapshot_digest"], doc_digest(snap))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
