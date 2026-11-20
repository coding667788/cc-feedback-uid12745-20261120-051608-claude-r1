"""Stable error codes for the local secure update client.

Every rejection is expressed as an :class:`UpdateError` carrying one of the
constants below.  The codes are part of the public contract documented in
README.md; tests and ``cases.json`` assert on them directly.
"""

from __future__ import annotations


class UpdateError(Exception):
    """A deterministic, machine-readable rejection."""

    def __init__(self, code: str, message: str = "", detail: dict | None = None) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message
        self.detail = detail or {}

    def as_dict(self) -> dict:
        return {"error_code": self.code, "error_message": self.message, "error_detail": self.detail}


# --- generic input ---------------------------------------------------------
E_INPUT_INVALID = "E_INPUT_INVALID"
E_UNKNOWN_TENANT = "E_UNKNOWN_TENANT"

# --- file sandbox ----------------------------------------------------------
E_PATH_ESCAPE = "E_PATH_ESCAPE"
E_FILE_MISSING = "E_FILE_MISSING"
E_FILE_DIGEST_MISMATCH = "E_FILE_DIGEST_MISMATCH"

# --- dual mirror -----------------------------------------------------------
E_MIRROR_MISSING = "E_MIRROR_MISSING"
E_MIRROR_DIVERGENCE = "E_MIRROR_DIVERGENCE"

# --- root trust algebra ----------------------------------------------------
E_ROOT_DOC_INVALID = "E_ROOT_DOC_INVALID"
E_ROLE_EXCLUSIVITY = "E_ROLE_EXCLUSIVITY"
E_ROOT_VERSION_ORDER = "E_ROOT_VERSION_ORDER"
E_ROOT_VERSION_SKIP = "E_ROOT_VERSION_SKIP"
E_ROOT_ROLLBACK = "E_ROOT_ROLLBACK"
E_ROOT_ANCHOR_MISMATCH = "E_ROOT_ANCHOR_MISMATCH"
E_ROOT_NOT_YET_VALID = "E_ROOT_NOT_YET_VALID"
E_ROOT_EXPIRED = "E_ROOT_EXPIRED"
E_ROOT_OLD_THRESHOLD = "E_ROOT_OLD_THRESHOLD"
E_ROOT_NEW_THRESHOLD = "E_ROOT_NEW_THRESHOLD"
E_ROOT_HOLDER_OVERLAP = "E_ROOT_HOLDER_OVERLAP"

# --- snapshot / targets ----------------------------------------------------
E_SNAPSHOT_INVALID = "E_SNAPSHOT_INVALID"
E_SNAPSHOT_VERSION_ROLLBACK = "E_SNAPSHOT_VERSION_ROLLBACK"
E_SNAPSHOT_VERSION_ORDER = "E_SNAPSHOT_VERSION_ORDER"
E_SNAPSHOT_CONFLICT = "E_SNAPSHOT_CONFLICT"
E_SNAPSHOT_EXPIRED = "E_SNAPSHOT_EXPIRED"
E_SNAPSHOT_NOT_YET_VALID = "E_SNAPSHOT_NOT_YET_VALID"
E_SNAPSHOT_THRESHOLD = "E_SNAPSHOT_THRESHOLD"
E_SNAPSHOT_UNAUTHORIZED = "E_SNAPSHOT_UNAUTHORIZED"
E_SNAPSHOT_NOT_CONFIRMED_ROOT = "E_SNAPSHOT_NOT_CONFIRMED_ROOT"

# --- target manifest -------------------------------------------------------
E_MANIFEST_INVALID = "E_MANIFEST_INVALID"
E_MANIFEST_VERSION_ROLLBACK = "E_MANIFEST_VERSION_ROLLBACK"
E_MANIFEST_CONFLICT = "E_MANIFEST_CONFLICT"
E_TARGET_MIXED_SNAPSHOT = "E_TARGET_MIXED_SNAPSHOT"
E_TARGET_NOT_IN_SNAPSHOT = "E_TARGET_NOT_IN_SNAPSHOT"
E_TARGET_DIGEST_MISMATCH = "E_TARGET_DIGEST_MISMATCH"
E_TARGET_PURPOSE = "E_TARGET_PURPOSE"
E_TARGET_PATH_MISMATCH = "E_TARGET_PATH_MISMATCH"
E_TARGET_CHANNEL = "E_TARGET_CHANNEL"
E_TARGET_NOT_CONFIRMED_ROOT = "E_TARGET_NOT_CONFIRMED_ROOT"
E_TARGET_UNAUTHORIZED = "E_TARGET_UNAUTHORIZED"
E_TARGET_PATH_UNAUTHORIZED = "E_TARGET_PATH_UNAUTHORIZED"
E_TARGET_THRESHOLD = "E_TARGET_THRESHOLD"
E_TARGET_EXPIRED = "E_TARGET_EXPIRED"
E_TARGET_NOT_YET_VALID = "E_TARGET_NOT_YET_VALID"

# --- signatures ------------------------------------------------------------
E_SIGNATURE_INVALID = "E_SIGNATURE_INVALID"
E_SIGNATURE_BAD_DIGEST = "E_SIGNATURE_BAD_DIGEST"
E_SIGNATURE_ROLE_UNAUTHORIZED = "E_SIGNATURE_ROLE_UNAUTHORIZED"
E_SIGNATURE_REPLAY = "E_SIGNATURE_REPLAY"

# --- time / rollback -------------------------------------------------------
E_TIME_ROLLBACK = "E_TIME_ROLLBACK"
E_ROLLBACK_DETECTED = "E_ROLLBACK_DETECTED"

# --- sqlite / concurrency --------------------------------------------------
E_CONCURRENCY_CONFLICT = "E_CONCURRENCY_CONFLICT"
E_STORE_BUSY = "E_STORE_BUSY"

# --- replay ----------------------------------------------------------------
E_REQUEST_REPLAY_CONFLICT = "E_REQUEST_REPLAY_CONFLICT"

# --- test-only crash fence -------------------------------------------------
E_SYNC_POINT_ABORTED = "E_SYNC_POINT_ABORTED"
