"""Trust-algebra unit tests: thresholds, seats, revocation, role separation."""

from __future__ import annotations

import unittest

from solution import docs as docmod
from solution.errors import UpdateError
from solution.signing import sign

from tests.support import (
    SNAP_ROLE,
    TGT_ROLE,
    TAG,
    TENANT,
    TenantHarness,
    domain,
    policy,
    root_v1,
    with_role,
)


class ThresholdSeatTests(TenantHarness):
    def test_two_holders_meet_threshold_two(self):
        target = self.build_target("svc-a", 1)
        report = docmod.role_signature_report(target, self.bootstrap_root, "target")
        self.assertTrue(report.accepted)
        self.assertEqual(sorted(report.holders), ["tgt-1", "tgt-2"])
        self.assertEqual(report.keys_used, ["t1", "t2"])

    def test_one_holder_with_two_keys_occupies_one_seat(self):
        spec = {
            "id": "svc-a",
            "version": 1,
            "root_version": 1,
            "snapshot_version": 1,
            "channel": "stable",
            "purpose": "runtime",
            "repo_tag": TAG,
            "path": "app/services/svc-a.bin",
            "payload": "text:x",
            "issued_at": 1000,
            "expires_at": 8000,
            "sign": [
                {"holder": "tgt-1", "key": "t1", "gen": 1},
                {"holder": "tgt-1", "key": "t1", "gen": 2},
            ],
        }
        target = self.session.build_target(spec)
        report = docmod.role_signature_report(target, self.bootstrap_root, "target")
        self.assertEqual(report.holders, ["tgt-1"])
        self.assertFalse(report.accepted)

    def test_identical_records_counted_as_duplicates(self):
        target = self.build_target("svc-a", 1)
        duplicate = dict(target["signatures"][0])
        target["signatures"] = [target["signatures"][0], duplicate]
        report = docmod.role_signature_report(target, self.bootstrap_root, "target")
        self.assertEqual(report.duplicates_skipped, 1)
        self.assertEqual(report.holders, ["tgt-1"])
        self.assertFalse(report.accepted)

    def test_revoked_generation_is_dropped(self):
        root = with_role(
            self.bootstrap_root,
            "target",
            policy("target", ["tgt-1", "tgt-2"], 2, tags=[TAG], paths=["app/services"],
                   revoked=[{"key_id": "t1", "gen": 1}]),
        )
        target = self.build_target("svc-a", 1)
        report = docmod.role_signature_report(target, root, "target")
        self.assertEqual(report.revoked, ["t1#1"])
        self.assertEqual(report.holders, ["tgt-2"])
        self.assertFalse(report.accepted)

    def test_revocation_only_voids_the_named_generation(self):
        root = with_role(
            self.bootstrap_root,
            "target",
            policy("target", ["tgt-1", "tgt-2"], 2, tags=[TAG], paths=["app/services"],
                   revoked=[{"key_id": "t1", "gen": 1}]),
        )
        target = self.build_target("svc-a", 1)
        target["signatures"] = [
            sign(target, "t1", 2, self.domain.secret("tgt-1", "t1"), "n-t1-gen2"),
            sign(target, "t2", 1, self.domain.secret("tgt-2", "t2"), "n-t2"),
        ]
        report = docmod.role_signature_report(target, root, "target")
        self.assertTrue(report.accepted)
        self.assertEqual(sorted(report.holders), ["tgt-1", "tgt-2"])

    def test_cross_role_key_is_a_violation(self):
        target = self.build_target("svc-a", 1)
        target["signatures"] = [
            sign(target, "s1", 1, self.domain.secret("snap-1", "s1"), "n-s1"),
        ]
        with self.assertRaises(UpdateError) as ctx:
            docmod.require_threshold(target, self.bootstrap_root, "target", "E_TARGET_THRESHOLD")
        self.assertEqual(ctx.exception.code, "E_SIGNATURE_ROLE_UNAUTHORIZED")

    def test_unknown_key_is_rejected(self):
        target = self.build_target("svc-a", 1)
        target["signatures"] = [
            sign(target, "ghost", 1, self.domain.secret("tgt-1", "t1"), "n-ghost"),
        ]
        with self.assertRaises(UpdateError) as ctx:
            docmod.require_threshold(target, self.bootstrap_root, "target", "E_TARGET_THRESHOLD")
        self.assertEqual(ctx.exception.code, "E_SIGNATURE_INVALID")

    def test_tampered_body_breaks_the_digest_binding(self):
        target = self.build_target("svc-a", 1)
        target["purpose"] = "totally-different"
        with self.assertRaises(UpdateError) as ctx:
            docmod.require_threshold(target, self.bootstrap_root, "target", "E_TARGET_THRESHOLD")
        self.assertEqual(ctx.exception.code, "E_SIGNATURE_BAD_DIGEST")


class RotationAlgebraTests(unittest.TestCase):
    def setUp(self):
        self.domain = domain()
        self.session = self.domain
        from solution.builder import Session

        self.builder = Session(self.domain, "rotation")
        self.v1 = self.builder.build_root(root_v1())
        self.v2 = self.builder.build_root(
            {
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
        )

    def test_disjoint_rotation_accepted(self):
        report = docmod.evaluate_rotation(self.v2, self.v1, self.v2)
        self.assertTrue(report.ok)
        self.assertEqual(sorted(report.old.holders), ["root-a", "root-b"])
        self.assertEqual(sorted(report.new.holders), ["root-c", "root-d"])
        # root-a and root-c sign validly on both sides, so both are shared
        # *candidates*; the chosen quorums are still disjoint.
        self.assertEqual(report.shared_holders, ["root-a", "root-c"])
        self.assertEqual(sorted(set(report.old.holders) & set(report.new.holders)), [])

    def test_shared_holder_is_not_double_counted(self):
        from solution.builder import Session

        builder = Session(self.domain, "rotation3")
        builder.build_root(root_v1())
        # old {a,b}, new {a,b}: the same two people cannot staff both quorums
        doc = builder.build_root(
            {
                "version": 2,
                "issued_at": 1100,
                "expires_at": 9200,
                "root": {"holders": ["root-a", "root-b"], "threshold": 2},
                "snapshot": dict(SNAP_ROLE),
                "target": dict(TGT_ROLE),
                "sign": [
                    {"holder": "root-a", "key": "a1"},
                    {"holder": "root-b", "key": "b1"},
                ],
            }
        )
        report = docmod.evaluate_rotation(doc, builder.roots[1], doc)
        self.assertFalse(report.ok)
        self.assertEqual(report.reason, "holder_overlap")
        self.assertEqual(report.shared_holders, ["root-a", "root-b"])

    def test_old_threshold_deficit_is_named(self):
        from solution.builder import Session

        builder = Session(self.domain, "rotation4")
        builder.build_root(root_v1())
        doc = builder.build_root(
            {
                "version": 2,
                "issued_at": 1100,
                "expires_at": 9200,
                "root": {"holders": ["root-c", "root-d"], "threshold": 2},
                "snapshot": dict(SNAP_ROLE),
                "target": dict(TGT_ROLE),
                "sign": [
                    {"holder": "root-c", "key": "c1"},
                    {"holder": "root-d", "key": "d1"},
                ],
            }
        )
        report = docmod.evaluate_rotation(doc, builder.roots[1], doc)
        self.assertFalse(report.ok)
        self.assertEqual(report.reason, "old_threshold")


class RoleExclusivityTests(TenantHarness):
    def test_same_holder_in_two_roles_is_rejected(self):
        from solution.builder import Session
        from solution.errors import UpdateError

        dom = domain()
        from solution.builder import Session as _S

        builder = _S(dom, "excl")
        doc = builder.build_root(
            root_v1(
                snapshot={"holders": ["root-a", "snap-1"], "threshold": 2, "tags": [TAG], "paths": ["app"]}
            )
        )
        with self.assertRaises(UpdateError) as ctx:
            docmod.parse_root(doc, TENANT)
        self.assertEqual(ctx.exception.code, "E_ROLE_EXCLUSIVITY")

    def test_role_path_prefix_is_segment_aware(self):
        writes = ["app/services/x", "lib/core/y"]
        ok, offending, tag = docmod.role_authorized(TGT_ROLE, TAG, writes)
        self.assertTrue(ok)
        ok, offending, tag = docmod.role_authorized(TGT_ROLE, TAG, ["app/servicesevil/x"])
        self.assertFalse(ok)
        self.assertEqual(offending, "app/servicesevil/x")

    def test_role_tag_is_enforced(self):
        ok, offending, tag = docmod.role_authorized(TGT_ROLE, "extra", ["app/services/x"])
        self.assertFalse(ok)
        self.assertEqual(tag, "extra")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
