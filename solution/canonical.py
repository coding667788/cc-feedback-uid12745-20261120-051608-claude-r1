"""Canonical encoding, digests and repository-path rules.

Everything that must be compared or signed goes through one canonical JSON
encoding (sorted keys, no whitespace, UTF-8, ``ensure_ascii=False``) so that
two encoders in different places cannot disagree about bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
from typing import Any

from .errors import UpdateError, E_INPUT_INVALID, E_PATH_ESCAPE

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# Path segments are deliberately narrow: no traversal, no drive letters, no
# alternate separators, no hidden-or-dot segments, no empty segments.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def canonical_json(value: Any) -> bytes:
    """Deterministic UTF-8 encoding used for every digest and signature."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_HEX.match(value))


def require_sha256(value: Any, field: str) -> str:
    if not is_sha256_hex(value):
        raise UpdateError(E_INPUT_INVALID, f"{field} must be a lowercase sha256 hex digest", {"field": field})
    return value


def normalize_repo_path(raw: Any) -> str:
    """Return a canonical POSIX repository path or raise ``E_PATH_ESCAPE``.

    Canonical form has no leading ``/``, no ``.``/``..``/empty segments and
    only ``[A-Za-z0-9._-]`` characters inside a segment.
    """
    if not isinstance(raw, str) or not raw:
        raise UpdateError(E_PATH_ESCAPE, "path must be a non-empty string", {"path": raw})
    if "\\" in raw or "\x00" in raw:
        raise UpdateError(E_PATH_ESCAPE, "path contains a forbidden character", {"path": raw})
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise UpdateError(E_PATH_ESCAPE, "absolute paths are not permitted", {"path": raw})
    parts = raw.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise UpdateError(E_PATH_ESCAPE, "path contains an empty, dot or parent segment", {"path": raw})
        if not _SEGMENT.match(part):
            raise UpdateError(E_PATH_ESCAPE, "path segment has an unsupported character", {"path": raw})
    canon = posixpath.normpath(raw)
    if canon != raw:
        raise UpdateError(E_PATH_ESCAPE, "path is not in canonical form", {"path": raw})
    return canon


def path_segments(raw: Any) -> tuple[str, ...]:
    return tuple(normalize_repo_path(raw).split("/"))


def is_under_prefix(path: str, prefixes: list[str]) -> bool:
    """True when ``path`` equals a prefix or lives beneath it.

    Prefixes themselves are validated as canonical paths; matching is on whole
    segments, so ``app/x`` never authorizes ``app/xevil``.
    """
    segs = tuple(path.split("/"))
    for prefix in prefixes:
        psegs = tuple(normalize_repo_path(prefix).split("/"))
        if len(psegs) <= len(segs) and segs[: len(psegs)] == psegs:
            return True
    return False


def repo_rel_to_fs(repo_path: str) -> str:
    """Convert a validated repo path to an OS-relative path below a sandbox root."""
    normalize_repo_path(repo_path)
    return os.path.join(*repo_path.split("/"))


def safe_join(root: str, repo_path: str) -> str:
    """Join ``repo_path`` under ``root`` and prove the result stays inside it."""
    rel = repo_rel_to_fs(repo_path)
    root_abs = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root_abs, rel))
    if candidate != root_abs and not candidate.startswith(root_abs + os.sep):
        raise UpdateError(E_PATH_ESCAPE, "resolved path escapes the sandbox root", {"path": repo_path})
    return candidate
