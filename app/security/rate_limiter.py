"""In-memory rate limiting mechanism for authentication endpoints."""

import threading
import time
from collections import defaultdict

from flask import current_app, request

# Thread-safe storage for timestamped attempt logs: key -> list of float timestamps
_lock = threading.Lock()
_attempt_history: dict[str, list[float]] = defaultdict(list)


def get_client_ip() -> str:
    """Retrieve client remote IP address safely."""
    return request.remote_addr or "127.0.0.1"


def is_rate_limited(
    key: str,
    max_attempts: int | None = None,
    window_seconds: int | None = None,
) -> bool:
    """Check whether a given key has exceeded the allowed attempt threshold within the window."""
    if max_attempts is None:
        max_attempts = current_app.config.get("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5)
    if window_seconds is None:
        window_seconds = current_app.config.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60)

    now = time.time()
    cutoff = now - window_seconds

    with _lock:
        # Prune expired timestamps
        timestamps = [ts for ts in _attempt_history[key] if ts > cutoff]
        _attempt_history[key] = timestamps
        return len(timestamps) >= max_attempts


def record_attempt(key: str) -> None:
    """Record an authentication attempt timestamp for the specified key."""
    now = time.time()
    with _lock:
        _attempt_history[key].append(now)


def reset_attempts(key: str) -> None:
    """Reset recorded attempts for a key following a successful authentication."""
    with _lock:
        _attempt_history.pop(key, None)


def clear_all_rate_limits() -> None:
    """Flush all rate-limiting state (primarily used in test teardown)."""
    with _lock:
        _attempt_history.clear()
