"""In-process rate limiter for login, submission, and messaging actions.

Uses a sliding-window counter keyed on (actor, action) tuples.  All state is
in-memory so it resets on restart — appropriate for a coursework system where
persistent rate-limit state (Redis, etc.) is out of scope.

Limits are intentionally conservative to deter brute-force and spam while
remaining transparent in logs.

Rate-limit policy (aligned with OWASP ASVS v4 §11.1.6 and NIST SP 800-63B §5.2.2):
  login     : 5 attempts per 5 minutes per username
  password  : same as login (shares the login bucket)
  message   : 10 messages per 60 seconds per sender
  submission: 5 uploads per 60 seconds per student
  profile   : 5 updates per 60 seconds per admin
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class _SlidingWindowRateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self.max_calls = max_calls
        self.window = window_seconds
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        """Return True if the action is within the rate limit; False if throttled."""
        now = time.monotonic()
        with self._lock:
            dq = self._timestamps[key]
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.max_calls:
                return False
            dq.append(now)
            return True

    def seconds_until_allowed(self, key: str) -> float:
        """Return how many seconds until the oldest entry falls out of the window."""
        now = time.monotonic()
        with self._lock:
            dq = self._timestamps[key]
            if not dq:
                return 0.0
            oldest = dq[0]
            wait = (oldest + self.window) - now
            return max(0.0, wait)

    def reset(self, key: str) -> None:
        """Clear rate-limit state for a key (e.g. after a successful login)."""
        with self._lock:
            self._timestamps.pop(key, None)


# Module-level singleton limiters — one per action category.
login_limiter = _SlidingWindowRateLimiter(max_calls=5, window_seconds=300)   # 5 per 5 min CHANGE 300
message_limiter = _SlidingWindowRateLimiter(max_calls=5, window_seconds=60) # 10 per min CHANGE 60
submission_limiter = _SlidingWindowRateLimiter(max_calls=5, window_seconds=60)#5 per min CHANGE 60
profile_update_limiter = _SlidingWindowRateLimiter(max_calls=5, window_seconds=60) # 5 per min CHANGE 60


def check_login_rate_limit(username: str) -> None:
    """Raise RateLimitError if login attempts for *username* are excessive."""
    if not login_limiter.is_allowed(username):
        wait = login_limiter.seconds_until_allowed(username)
        raise RateLimitError(
            f"Too many login attempts for '{username}'. "
            f"Try again in {int(wait) + 1} seconds."
        )


def check_message_rate_limit(sender: str) -> None:
    """Raise RateLimitError if *sender* is sending messages too rapidly."""
    if not message_limiter.is_allowed(sender):
        wait = message_limiter.seconds_until_allowed(sender)
        raise RateLimitError(
            f"Message rate limit exceeded. Try again in {int(wait) + 1} seconds."
        )


def check_submission_rate_limit(student: str) -> None:
    """Raise RateLimitError if *student* is uploading assignments too rapidly."""
    if not submission_limiter.is_allowed(student):
        wait = submission_limiter.seconds_until_allowed(student)
        raise RateLimitError(
            f"Submission rate limit exceeded. Try again in {int(wait) + 1} seconds."
        )


def check_profile_update_rate_limit(admin: str) -> None:
    """Raise RateLimitError if *admin* is updating profiles too rapidly."""
    if not profile_update_limiter.is_allowed(admin):
        wait = profile_update_limiter.seconds_until_allowed(admin)
        raise RateLimitError(
            f"Profile update rate limit exceeded. Try again in {int(wait) + 1} seconds."
        )


class RateLimitError(Exception):
    """Raised when an action is throttled by the rate limiter."""