"""
Minimal in-memory sliding-window rate limiter for the auth endpoints.

Prototype-appropriate: per-process, no external store. Production would move
this to Redis (per the architecture) or enforce at the reverse proxy; the
call sites wouldn't change.
"""
import time
from collections import defaultdict, deque

_hits: dict[str, deque] = defaultdict(deque)


def allow(key: str, limit: int, window_seconds: int) -> bool:
    """True if `key` has had fewer than `limit` hits in the last window."""
    now = time.monotonic()
    q = _hits[key]
    while q and q[0] <= now - window_seconds:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


def reset(key_prefix: str = "") -> None:
    """Testing hook: clear counters (optionally only those with a prefix)."""
    if not key_prefix:
        _hits.clear()
        return
    for k in [k for k in _hits if k.startswith(key_prefix)]:
        del _hits[k]
