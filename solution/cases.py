"""Declarative case runner.

``cases.json`` is a *replayable recipe*, not a recording of outputs: it holds
the tenant layout, the key material, the documents to synthesise and the steps
to run.  Replaying it rebuilds every package byte-for-byte from scratch.

Case shape::

    {
      "cases": [
        {
          "name": "happy-path",
          "tenant": {"tenant": "acme", "holders": {...}},
          "bootstrap": {"root": {...root spec...}, "trusted_time": 1000},
          "steps": [
            {"kind": "update", "build": {...}, "trusted_time": 1010,
             "request_id": "r1",
             "expect": {"outcome": "committed", "root_version": 3}},
            {"kind": "query", "expect": {...}}
          ]
        }
      ]
    }

A step either qualifies as ``update`` (build + prepare + publish) or
``query`` (read-only assertions against fixed versions).  ``expect`` holds the
*expected* result; the runner compares and records a per-step verdict.
"""

from __future__ import annotations

import json
import os
import shutil

from .builder import Domain, Session, write_package
from .canonical import canonical_json
from .docs import doc_digest
from .errors import UpdateError
from .state import Store
from .updater import Updater


# --------------------------------------------------------------------------
# tiny assertion helpers used by the runner
# --------------------------------------------------------------------------
class ExpectationFailure(AssertionError):
    pass


def _get_path(value, path):
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return None, False
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None, False
        else:
            return None, False
    return current, True


def _matches(actual, expected) -> bool:
    """Subset match: every key in ``expected`` must equal the actual value."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(key in actual and _matches(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return False
        return all(_matches(a, e) for a, e in zip(actual, expected))
    return actual == expected


def check_expectations(actual: dict, expected: dict) -> list:
    """Return a list of human-readable mismatch descriptions."""
    problems = []
    for key, want in expected.items():
        got = actual.get(key)
        if key == "error_code":
            if got != want:
                problems.append(f"error_code: expected {want!r}, got {got!r}")
        elif not _matches(got, want):
            problems.append(f"{key}: expected {want!r}, got {got!r}")
    return problems


# --------------------------------------------------------------------------
# package synthesis for one update step
# --------------------------------------------------------------------------
class CaseWorkspace:
    def __init__(self, case_name: str, root_dir: str) -> None:
        self.case_name = case_name
        self.root_dir = root_dir
        self.db_path = os.path.join(root_dir, "state.db")
        self.package_root = os.path.join(root_dir, "packages")
        os.makedirs(self.package_root, exist_ok=True)
        self.store = Store(self.db_path)
        self.updater = Updater(self.store)
        self.session: Session | None = None
        self.domain: Domain | None = None

    def close(self) -> None:
        self.store.close()


def build_case_documents(workspace: CaseWorkspace, spec: dict) -> tuple:
    """Build every document named by ``spec`` and return ``(docs, files)``."""
    session = workspace.session
    assert session is not None
    for root_spec in spec.get("roots", []):
        session.build_root(root_spec)
    for target_spec in spec.get("targets", []):
        session.build_target(target_spec)
    for snap_spec in spec.get("snapshots", []):
        entries = []
        for entry_spec in snap_spec.get("entries", []):
            parts = entry_spec["target"].split(":")
            target_doc = session.targets[(parts[0], int(parts[1]))]
            entries.append(session.make_entry(target_doc, entry_spec.get("override")))
        session.build_snapshot(snap_spec, entries)

    docs = []
    for ref in spec["documents"]:
        parts = ref.split(":")
        if parts[0] == "root":
            docs.append(session.roots[int(parts[1])])
        elif parts[0] == "snapshot":
            docs.append(session.snapshots[(parts[1], int(parts[2]))])
        elif parts[0] == "target":
            docs.append(session.targets[(parts[1], int(parts[2]))])
        else:
            raise UpdateError("E_INPUT_INVALID", f"unknown document ref {ref!r}")

    files = {}
    for rel_path, payload_spec in spec.get("files", {}).items():
        files[rel_path] = Session.payload_bytes(payload_spec)
    # Any target that is included in the package normally also carries its file.
    for doc in docs:
        if doc["doc_type"] == "target" and doc["path"] not in files:
            for target_spec in spec.get("targets", []):
                if target_spec["id"] == doc["target_id"] and int(target_spec["version"]) == doc["version"]:
                    files[doc["path"]] = Session.payload_bytes(target_spec["payload"])
                    break
    files.pop("__omit__", None)
    return docs, files


def write_case_package(workspace: CaseWorkspace, package_name: str, docs: list, files: dict, spec: dict) -> str:
    package_dir = os.path.join(workspace.package_root, package_name)
    if os.path.isdir(package_dir):
        shutil.rmtree(package_dir)
    os.makedirs(package_dir)
    mutations = spec.get("mutations", {})
    omit = mutations.get("omit_from_mirror", {})
    override = {}
    for mirror, mapping in mutations.get("mirror_override", {}).items():
        override[mirror] = {
            rel_path: Session.payload_bytes(payload) for rel_path, payload in mapping.items()
        }
    raw_docs = {}
    if mutations.get("non_canonical_document"):
        ref = mutations["non_canonical_document"]
        for doc in docs:
            text = doc["doc_type"] + (f":{doc.get('version')}")
            if text == ref:
                raw_docs[id(doc)] = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")
                break
        else:
            raise UpdateError("E_INPUT_INVALID", f"non_canonical_document ref {ref!r} not found")

    index_extra = mutations.get("index_extra")
    return write_package(
        package_dir,
        workspace.domain.tenant,
        docs,
        files,
        omit_from_mirror=omit,
        mirror_override=override,
        raw_doc_bytes=raw_docs,
        index_extra=index_extra,
    )


# --------------------------------------------------------------------------
# per-step execution
# --------------------------------------------------------------------------
def run_update_step(workspace: CaseWorkspace, step: dict) -> dict:
    spec = step["build"]
    docs, files = build_case_documents(workspace, spec)
    package_dir = write_case_package(workspace, step["package_name"], docs, files, spec)
    trusted_time = int(step["trusted_time"])
    request_id = step.get("request_id", "req")
    try:
        plan = workspace.updater.prepare(workspace.domain.tenant, package_dir, request_id, trusted_time)
        if step.get("dry_run"):
            return {
                "status": "prepared",
                "root_before": plan.root_before["version"],
                "root_after": plan.root_after["version"],
                "root_steps": len(plan.root_steps),
                "channels": {s.doc["channel"]: s.doc["version"] for s in plan.snapshots},
                "targets": {t.doc["target_id"]: t.doc["version"] for t in plan.targets},
                "trust_table": plan.trust_table(),
                "package_digest": plan.package_digest,
            }
        outcome = workspace.updater.publish(plan)
        receipt = outcome["receipt"]
        return {
            "status": outcome["status"],
            "root_version": receipt["root_after"]["version"],
            "root_digest": receipt["root_after"]["digest"],
            "root_steps": receipt["root_steps"],
            "channels": {name: info["version"] for name, info in receipt["channels"].items()},
            "targets": {name: info["version"] for name, info in receipt["targets"].items()},
            "receipt_digest": receipt["receipt_digest"],
            "trust_table": receipt["trust_table"],
            "package_digest": receipt["package_digest"],
        }
    except UpdateError as exc:
        return {"status": "rejected", **exc.as_dict()}


def run_query_step(workspace: CaseWorkspace, step: dict) -> dict:
    query = step["query"]
    kind = query["kind"]
    tenant = workspace.domain.tenant
    if kind == "audit":
        result = workspace.store.audit(tenant)
        result["status"] = "ok"
        return result
    if kind == "channel":
        info = workspace.store.read_channel(tenant, query["channel"], query.get("version"))
        return {
            "status": "ok",
            "channel": info["channel"],
            "version": info["version"],
            "snapshot_digest": info["snapshot_digest"],
            "root_version": info["root_version"],
            "entries": len(info["snapshot"]["entries"]),
        }
    if kind == "target":
        info = workspace.store.read_target(tenant, query["target_id"], query.get("version"))
        return {"status": "ok", **{k: v for k, v in info.items() if k != "tenant"}}
    if kind == "root":
        info = workspace.store.read_root(tenant, query.get("version"))
        return {
            "status": "ok",
            "version": info["version"],
            "digest": info["digest"],
            "root_version": info["root"]["version"],
        }
    raise UpdateError("E_INPUT_INVALID", f"unknown query kind {kind!r}")


# --------------------------------------------------------------------------
# case execution
# --------------------------------------------------------------------------
def run_case(case: dict, work_root: str) -> dict:
    name = case["name"]
    case_dir = os.path.join(work_root, name)
    if os.path.isdir(case_dir):
        shutil.rmtree(case_dir)
    os.makedirs(case_dir, exist_ok=True)

    domain = Domain(case["tenant"])
    workspace = CaseWorkspace(name, case_dir)
    workspace.domain = domain
    workspace.session = Session(domain, name)

    step_results = []
    failure = None
    try:
        bootstrap = case["bootstrap"]
        session = workspace.session
        # Build the bootstrap root; if it is not v1, build the chain leading
        # to it so ``previous_digest`` links are genuine.
        chain = bootstrap.get("chain") or []
        for root_spec in chain:
            session.build_root(root_spec)
        anchor = session.build_root(bootstrap["root"])
        workspace.store.install_anchor(
            domain.tenant, anchor, doc_digest(anchor), int(bootstrap["trusted_time"])
        )
        step_results.append(
            {
                "step": "bootstrap",
                "ok": True,
                "actual": {
                    "root_version": anchor["version"],
                    "root_digest": doc_digest(anchor),
                    "trusted_time": int(bootstrap["trusted_time"]),
                },
                "problems": [],
            }
        )

        for index, step in enumerate(case.get("steps", []), start=1):
            if step["kind"] == "update":
                actual = run_update_step(workspace, step)
            elif step["kind"] == "query":
                actual = run_query_step(workspace, step)
            else:
                raise UpdateError("E_INPUT_INVALID", f"unknown step kind {step['kind']!r}")
            problems = check_expectations(actual, step.get("expect", {}))
            step_results.append(
                {
                    "step": index,
                    "ok": not problems,
                    "actual": actual,
                    "problems": problems,
                }
            )
            if problems:
                failure = f"step {index} ({step.get('label', step['kind'])}) did not match expectations"
                break
    except UpdateError as exc:
        failure = f"{exc.code}: {exc.message}"
        step_results.append({"step": "error", "ok": False, "actual": exc.as_dict()})
    finally:
        workspace.close()

    return {
        "case": name,
        "ok": failure is None,
        "failure": failure,
        "steps": step_results,
    }


def run_cases(cases_doc: dict, work_root: str) -> dict:
    results = []
    for case in cases_doc["cases"]:
        results.append(run_case(case, work_root))
    passed = sum(1 for result in results if result["ok"])
    return {
        "format": "simupd-results/1",
        "cases": results,
        "summary": {"total": len(results), "passed": passed, "failed": len(results) - passed},
    }


def load_cases(path: str) -> dict:
    with open(path, "rb") as handle:
        data = json.loads(handle.read().decode("utf-8"))
    if not isinstance(data, dict) or "cases" not in data:
        raise UpdateError("E_INPUT_INVALID", "cases file must be an object with a 'cases' list")
    return data


def write_results(path: str, results: dict) -> None:
    payload = canonical_json(results)
    with open(path, "wb") as handle:
        handle.write(payload)
        handle.write(b"\n")
