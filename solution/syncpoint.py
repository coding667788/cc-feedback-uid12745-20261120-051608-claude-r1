"""Deterministic crash fences used by the process-termination tests.

A *sync point* is a named position in the pipeline.  When the environment
variable ``SIMUPD_SYNC_POINT`` names it, the process is terminated on the
spot:

* action ``exit`` (default) calls ``os._exit`` after flushing, so no
  ``atexit`` hooks, no buffer flushes and no SQLite ``COMMIT`` run.  This is
  how the tests simulate a machine dying at a specific instant.
* action ``raise`` raises :class:`SyncPointAbort` instead, so the same fence
  can be exercised inside the test process.

The fence is inert unless explicitly requested, so production paths never
carry a hidden branch.
"""

from __future__ import annotations

import os
import sys

from .errors import E_SYNC_POINT_ABORTED, UpdateError

ENV_POINT = "SIMUPD_SYNC_POINT"
ENV_ACTION = "SIMUPD_SYNC_POINT_ACTION"
EXIT_CODE = 97


class SyncPointAbort(UpdateError):
    def __init__(self, point: str) -> None:
        super().__init__(E_SYNC_POINT_ABORTED, f"terminated at sync point {point!r}", {"sync_point": point})


def hit(point: str) -> None:
    """Terminate (or abort) if this process was told to stop at ``point``."""
    requested = os.environ.get(ENV_POINT)
    if requested != point:
        return
    action = os.environ.get(ENV_ACTION, "exit").lower()
    if action == "raise":
        raise SyncPointAbort(point)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:  # pragma: no cover - best effort only
        pass
    os._exit(EXIT_CODE)


def points() -> tuple[str, ...]:
    return ("before_publish_commit", "after_commit_before_return")
