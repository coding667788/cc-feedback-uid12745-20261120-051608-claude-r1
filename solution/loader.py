"""Update-package loading: dual mirrors, byte identity, sandboxed reads.

A package directory looks like::

    package/
      index.json          # names the mirror directories and every file
      mirror-a/<rel>      # documents and payload files
      mirror-b/<rel>      # must be byte-identical to mirror-a

Nothing in ``index.json`` is trusted beyond the *list of relative paths*: each
path is validated as a canonical repository path, every read is confined to
the package directory, and every document must appear in **both** mirrors
with identical bytes.  A missing file in a mirror is ``E_MIRROR_MISSING``; two
mirrors that disagree are ``E_MIRROR_DIVERGENCE``.

Documents must additionally be stored in canonical JSON form.  That makes the
bytes on disk the signed artefact and stops whitespace/key-order smuggling
between the signature and the parser.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .canonical import canonical_json, normalize_repo_path, safe_join, sha256_hex
from .docs import doc_key_text
from .errors import (
    E_INPUT_INVALID,
    E_MIRROR_DIVERGENCE,
    E_MIRROR_MISSING,
    E_PATH_ESCAPE,
    UpdateError,
)

PACKAGE_FORMAT = "simupd-package/1"


@dataclass(frozen=True)
class MirrorFile:
    """One logical file plus the bytes observed in each mirror."""

    rel_path: str
    bytes_by_mirror: dict
    digest: str

    @property
    def content(self) -> bytes:
        return next(iter(self.bytes_by_mirror.values()))

    @property
    def size(self) -> int:
        return len(self.content)


@dataclass
class LoadedPackage:
    tenant: str
    package_dir: str
    mirrors: tuple
    index_path: str
    index_digest: str
    docs: dict = field(default_factory=dict)       # identity text -> doc
    doc_bytes: dict = field(default_factory=dict)  # identity text -> {mirror: bytes}
    files: dict = field(default_factory=dict)      # repo path -> MirrorFile

    # -- typed accessors ---------------------------------------------------
    def roots(self) -> dict:
        return {doc["version"]: doc for doc in self.docs.values() if doc["doc_type"] == "root"}

    def snapshots(self) -> list:
        return [doc for doc in self.docs.values() if doc["doc_type"] == "snapshot"]

    def targets(self) -> list:
        return [doc for doc in self.docs.values() if doc["doc_type"] == "target"]

    def doc_bytes_for(self, doc: dict) -> dict:
        return self.doc_bytes[doc_key_text(doc)]

    def all_input_digests(self) -> dict:
        """Canonical digest of every input, used for in-transaction re-checks."""
        digests = {"index.json": self.index_digest}
        for key, blobs in self.doc_bytes.items():
            digests["doc:" + key] = sha256_hex(blobs[self.mirrors[0]])
        for rel_path, entry in self.files.items():
            digests["file:" + rel_path] = entry.digest
        return digests


class PackageReader:
    """Reads and cross-checks a package directory."""

    def __init__(self, package_dir: str) -> None:
        self.package_dir = os.path.realpath(package_dir)

    # -- primitives --------------------------------------------------------
    def _read(self, mirror: str, rel_path: str) -> bytes:
        try:
            abs_path = safe_join(self.package_dir, mirror + "/" + rel_path)
        except UpdateError as exc:
            raise UpdateError(E_PATH_ESCAPE, "package path escapes the package directory", exc.detail) from None
        if not os.path.isfile(abs_path):
            raise UpdateError(
                E_MIRROR_MISSING, f"mirror {mirror} is missing {rel_path}",
                {"mirror": mirror, "path": rel_path},
            )
        with open(abs_path, "rb") as handle:
            return handle.read()

    def _read_both(self, mirrors: tuple, rel_path: str, what: str) -> dict:
        blobs = {mirror: self._read(mirror, rel_path) for mirror in mirrors}
        reference = blobs[mirrors[0]]
        for mirror in mirrors[1:]:
            if blobs[mirror] != reference:
                raise UpdateError(
                    E_MIRROR_DIVERGENCE,
                    f"mirrors disagree on {what} {rel_path}",
                    {"path": rel_path, "digest_by_mirror": {m: sha256_hex(b) for m, b in blobs.items()}},
                )
        return blobs

    # -- public ------------------------------------------------------------
    def load(self) -> LoadedPackage:
        if not os.path.isdir(self.package_dir):
            raise UpdateError(E_INPUT_INVALID, "package directory does not exist", {"package_dir": self.package_dir})
        index_path = os.path.join(self.package_dir, "index.json")
        if not os.path.isfile(index_path):
            raise UpdateError(E_INPUT_INVALID, "package/index.json is missing", {"package_dir": self.package_dir})
        with open(index_path, "rb") as handle:
            index_raw = handle.read()
        try:
            index = json.loads(index_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError(E_INPUT_INVALID, "index.json is not valid UTF-8 JSON", {"reason": str(exc)}) from None
        if not isinstance(index, dict) or index.get("format") != PACKAGE_FORMAT:
            raise UpdateError(
                E_INPUT_INVALID, "index.json has an unsupported format",
                {"format": index.get("format") if isinstance(index, dict) else None},
            )
        tenant = index.get("tenant")
        if not isinstance(tenant, str) or not tenant:
            raise UpdateError(E_INPUT_INVALID, "index.json lacks a tenant")
        mirrors = index.get("mirrors")
        if not isinstance(mirrors, list) or len(mirrors) != 2 or any(not isinstance(m, str) for m in mirrors):
            raise UpdateError(E_INPUT_INVALID, "a package must declare exactly two mirrors")
        if mirrors[0] == mirrors[1]:
            raise UpdateError(E_INPUT_INVALID, "the two mirrors must be distinct directories")
        for mirror in mirrors:
            normalize_repo_path(mirror)
            if not os.path.isdir(os.path.join(self.package_dir, mirror)):
                raise UpdateError(E_MIRROR_MISSING, f"mirror directory {mirror} is missing", {"mirror": mirror})
        mirror_tuple = tuple(mirrors)

        package = LoadedPackage(
            tenant=tenant,
            package_dir=self.package_dir,
            mirrors=mirror_tuple,
            index_path=index_path,
            index_digest=sha256_hex(index_raw),
        )

        doc_paths = index.get("documents")
        if not isinstance(doc_paths, list) or not doc_paths:
            raise UpdateError(E_INPUT_INVALID, "index.documents must be a non-empty list")
        seen_paths: set = set()
        for rel_path in doc_paths:
            if not isinstance(rel_path, str):
                raise UpdateError(E_INPUT_INVALID, "index.documents entries must be strings")
            normalize_repo_path(rel_path)
            if rel_path in seen_paths:
                raise UpdateError(E_INPUT_INVALID, "index.documents lists a path twice", {"path": rel_path})
            seen_paths.add(rel_path)
            blobs = self._read_both(mirror_tuple, rel_path, "document")
            doc = self._decode_doc(rel_path, blobs[mirror_tuple[0]])
            key = doc_key_text(doc)
            if key in package.docs:
                raise UpdateError(E_INPUT_INVALID, "package contains the same document twice", {"identity": key})
            package.docs[key] = doc
            package.doc_bytes[key] = blobs

        file_paths = index.get("files", [])
        if not isinstance(file_paths, list):
            raise UpdateError(E_INPUT_INVALID, "index.files must be a list")
        for rel_path in file_paths:
            if not isinstance(rel_path, str):
                raise UpdateError(E_INPUT_INVALID, "index.files entries must be strings")
            normalize_repo_path(rel_path)
            if rel_path in package.files:
                raise UpdateError(E_INPUT_INVALID, "index.files lists a path twice", {"path": rel_path})
            blobs = self._read_both(mirror_tuple, rel_path, "payload file")
            package.files[rel_path] = MirrorFile(
                rel_path=rel_path,
                bytes_by_mirror=blobs,
                digest=sha256_hex(blobs[mirror_tuple[0]]),
            )
        return package

    @staticmethod
    def _decode_doc(rel_path: str, raw: bytes) -> dict:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError(
                E_INPUT_INVALID, f"document {rel_path} is not valid UTF-8 JSON",
                {"path": rel_path, "reason": str(exc)},
            ) from None
        if not isinstance(doc, dict):
            raise UpdateError(E_INPUT_INVALID, f"document {rel_path} is not a JSON object", {"path": rel_path})
        if doc.get("doc_type") not in ("root", "snapshot", "target"):
            raise UpdateError(
                E_INPUT_INVALID, f"document {rel_path} has an unknown doc_type", {"path": rel_path}
            )
        if not isinstance(doc.get("signatures"), list):
            raise UpdateError(E_INPUT_INVALID, f"document {rel_path} has no signatures list", {"path": rel_path})
        if canonical_json(doc) != raw:
            raise UpdateError(
                E_INPUT_INVALID,
                f"document {rel_path} is not in canonical encoding",
                {
                    "path": rel_path,
                    "actual_digest": sha256_hex(raw),
                    "canonical_digest": sha256_hex(canonical_json(doc)),
                },
            )
        return doc

