"""Replaying ``cases.json`` and the CLI contract.

These tests are deliberately *end-to-end*: they invoke ``python -m solution``
exactly as the README documents, on the shipped ``cases.json``, and assert the
concrete exit code and the concrete per-case verdicts.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from solution.cases import load_cases, run_cases

from tests.support import REPO_ROOT


CASES_PATH = os.path.join(REPO_ROOT, "cases.json")


class CasesFileTests(unittest.TestCase):
    def test_cases_file_is_present_and_well_formed(self):
        self.assertTrue(os.path.isfile(CASES_PATH), "cases.json must ship with the solution")
        doc = load_cases(CASES_PATH)
        self.assertEqual(doc["format"], "simupd-cases/1")
        names = [case["name"] for case in doc["cases"]]
        self.assertEqual(len(names), len(set(names)), "case names must be unique")
        self.assertGreaterEqual(len(names), 10)

    def test_every_case_declares_expectations(self):
        doc = load_cases(CASES_PATH)
        for case in doc["cases"]:
            steps = case.get("steps", [])
            self.assertTrue(steps, f"{case['name']} has no steps")
            for step in steps:
                self.assertIn("expect", step, f"{case['name']} has a step without expectations")

    def test_all_cases_replay_green(self):
        doc = load_cases(CASES_PATH)
        work_root = tempfile.mkdtemp(prefix="simupd-cases-replay-")
        self.addCleanup(shutil.rmtree, work_root, ignore_errors=True)
        results = run_cases(doc, work_root)
        failures = [case for case in results["cases"] if not case["ok"]]
        self.assertEqual(failures, [], json.dumps(failures, indent=2)[:4000])
        self.assertEqual(results["summary"]["failed"], 0)
        self.assertEqual(results["summary"]["passed"], len(doc["cases"]))

    def test_replay_is_deterministic(self):
        doc = load_cases(CASES_PATH)
        first_root = tempfile.mkdtemp(prefix="simupd-det-a-")
        second_root = tempfile.mkdtemp(prefix="simupd-det-b-")
        self.addCleanup(shutil.rmtree, first_root, ignore_errors=True)
        self.addCleanup(shutil.rmtree, second_root, ignore_errors=True)
        first = run_cases(doc, first_root)
        second = run_cases(doc, second_root)
        self.assertEqual(first, second)

    def test_negative_cases_expect_the_documented_codes(self):
        doc = load_cases(CASES_PATH)
        expected = {
            case["name"]: [
                step["expect"].get("error_code")
                for step in case["steps"]
                if step["expect"].get("error_code")
            ]
            for case in doc["cases"]
        }
        self.assertIn("E_ROOT_ROLLBACK", expected["02-reject-root-rollback"])
        self.assertIn("E_ROOT_OLD_THRESHOLD", expected["03-reject-old-root-quorum-missing"])
        self.assertIn("E_ROOT_NEW_THRESHOLD", expected["04-reject-shared-holder-fills-both-seats"])
        self.assertIn("E_TARGET_THRESHOLD", expected["05-reject-duplicate-key-one-seat"])
        self.assertIn("E_MANIFEST_VERSION_ROLLBACK", expected["06-reject-target-version-floor"])
        self.assertIn("E_TARGET_PATH_MISMATCH", expected["08-reject-mixed-snapshot-target"])
        self.assertIn("E_SNAPSHOT_EXPIRED", expected["09-reject-expired-exact"])
        self.assertIn("E_ROOT_OLD_THRESHOLD", expected["10-reject-root-role-duplicate-signer"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="simupd-cli-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "solution", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def test_cli_writes_result_and_exits_zero(self):
        output = os.path.join(self.tmp, "result.json")
        proc = self._run("--input", CASES_PATH, "--output", output)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(output, "rb") as handle:
            result = json.load(handle)
        self.assertEqual(result["format"], "simupd-results/1")
        self.assertEqual(result["summary"]["failed"], 0)
        # Every case result carries the concrete step outcomes.
        for case in result["cases"]:
            self.assertTrue(case["ok"])
            for step in case["steps"]:
                self.assertIn("actual", step)
                self.assertIn("problems", step)
                self.assertEqual(step["problems"], [])

    def test_cli_missing_input_exits_two(self):
        proc = self._run("--input", os.path.join(self.tmp, "nope.json"), "--output", "x.json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot read cases", proc.stderr)

    def test_cli_malformed_input_exits_two(self):
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        proc = self._run("--input", bad, "--output", os.path.join(self.tmp, "o.json"))
        self.assertEqual(proc.returncode, 2)

    def test_cli_missing_required_argument_exits_two(self):
        proc = self._run("--input", CASES_PATH)
        self.assertEqual(proc.returncode, 2)

    def test_cli_reports_failure_for_a_case_that_does_not_match(self):
        doc = load_cases(CASES_PATH)
        tampered = json.loads(json.dumps(doc))
        first = tampered["cases"][0]
        first["steps"][0]["expect"]["root_version"] = 99  # deliberately wrong
        path = os.path.join(self.tmp, "wrong.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(tampered, handle)
        output = os.path.join(self.tmp, "r.json")
        proc = self._run("--input", path, "--output", output)
        self.assertEqual(proc.returncode, 1)
        with open(output, "rb") as handle:
            result = json.load(handle)
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertEqual(result["cases"][0]["case"], first["name"])
        self.assertTrue(result["cases"][0]["steps"][1]["problems"])


class ExecutionDocsTests(unittest.TestCase):
    """The README's claimed invocation strings must actually work."""

    def test_readme_states_both_entrypoints(self):
        readme = os.path.join(REPO_ROOT, "README.md")
        self.assertTrue(os.path.isfile(readme))
        with open(readme, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("python -m solution --input cases.json --output result.json", text)
        self.assertIn("python -m unittest discover -s tests -v", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
