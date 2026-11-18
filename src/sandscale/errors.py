# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Typed errors.

Every error for an answer of the Sandscale API is a :class:`SandscaleError` carrying the
server's own ``code`` and ``message``. The subclasses only sort those answers so callers can
catch a family (limits, entitlement, region, kill switch); the server decides every refusal,
the SDK never refuses a call on its own.
"""

from __future__ import annotations

import email.utils
import json
import re
import time
from typing import Any, Mapping, Optional


class ConfigurationError(Exception):
    """Raised before any call when the client cannot be configured safely."""


class SandscaleError(Exception):
    """An answer of the Sandscale API that is not a success."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        request_id: Optional[str] = None,
        details: Any = None,
        region: Optional[str] = None,
        retry_after: float = 0.0,
    ) -> None:
        super().__init__(message)
        #: HTTP status of the answer (0 when no answer was received).
        self.status = status
        #: The server's error code, e.g. ``quota_exceeded``, ``kill_switch_engaged``.
        self.code = code
        self.message = message
        #: The server's request id; quote it when you contact support.
        self.request_id = request_id
        #: Structured details the server sent (``error.detail`` or ``error.details``).
        self.details = details
        #: The region the server names in the answer (``wrong_region`` answers carry it).
        self.region = region
        #: Seconds the server asked to wait (Retry-After); 0 when it did not say.
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status}, code={self.code!r}, message={self.message!r})"


class InvalidRequestError(SandscaleError):
    """400, 413 or 422: the request was refused as invalid."""


class AuthenticationError(SandscaleError):
    """401: the API key or token is missing, expired, revoked or of another region."""


class PermissionDeniedError(SandscaleError):
    """403: the caller may not do this (role, policy, host access rules)."""


class NotFoundError(SandscaleError):
    """404: not found, or not visible to the caller."""


class ConflictError(SandscaleError):
    """409: the resource is not in a state that allows the call (paused, ended, busy)."""


class LimitExceededError(SandscaleError):
    """A plan, quota or usage limit refused the call (402, or a quota or limit code)."""


class RateLimitError(LimitExceededError):
    """429: too many requests; retry after ``retry_after`` seconds."""


class EntitlementError(SandscaleError):
    """The organization's plan does not include this, or payment is required."""


class RegionError(SandscaleError):
    """The call went to a region that cannot serve it (wrong region, region unavailable)."""


class KillSwitchError(SandscaleError):
    """A kill switch (the organization's or Sandscale's) stopped the call."""


class ServerError(SandscaleError):
    """5xx: the server could not answer the call."""

    @property
    def retryable(self) -> bool:
        """True when the same call may succeed a moment later (502, 503 and 504 answers)."""
        return self.status in (502, 503, 504)


class ServiceUnavailableError(ServerError):
    """503: the service cannot answer now and says so; retry after ``retry_after`` seconds."""


class SandboxWakingError(ServiceUnavailableError):
    """503 ``sandbox_waking``: the sandbox is resuming from a pause; retry after ``retry_after``."""


class APIConnectionError(SandscaleError):
    """No answer: the connection failed or the call timed out."""

    def __init__(self, message: str) -> None:
        super().__init__(0, "connection_error", message)


_ENTITLEMENT_CODES = {"not_entitled", "payment_required", "service_not_entitled"}
#: 503 codes that are a moment's refusal (fail closed), never an entitlement answer.
_UNAVAILABLE_CODES = {"entitlement_unavailable"}
_KILL_SWITCH = re.compile(r"(^|_)kill_switch")
_LIMIT = re.compile(r"(^|_)quota(_|$)|(^|_)limit(_|$)|limit_exceeded$")
_BY_STATUS: dict[int, type[SandscaleError]] = {
    400: InvalidRequestError,
    413: InvalidRequestError,
    422: InvalidRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
}


def error_for(status: int, code: str, message: str, **extra: Any) -> SandscaleError:
    """Sorts a server answer into its error class."""
    cls: type[SandscaleError]
    if _KILL_SWITCH.search(code):
        cls = KillSwitchError
    elif code == "wrong_region" or code.startswith("region_"):
        cls = RegionError
    elif code == "sandbox_waking":
        cls = SandboxWakingError
    elif code in _UNAVAILABLE_CODES:
        cls = ServiceUnavailableError
    elif code in _ENTITLEMENT_CODES or code.startswith(("entitlement_", "plan_")) or code.endswith("_not_in_plan"):
        cls = EntitlementError
    elif status == 429:
        cls = RateLimitError
    elif status == 402 or _LIMIT.search(code):
        cls = LimitExceededError
    elif status in _BY_STATUS:
        cls = _BY_STATUS[status]
    elif status == 503:
        cls = ServiceUnavailableError
    elif status >= 500:
        cls = ServerError
    else:
        cls = SandscaleError
    return cls(status, code, message, **extra)


def parse_error(status: int, reason: str, text: str, headers: Mapping[str, str]) -> SandscaleError:
    """Reads Keystone's error envelope ``{"error": {"code", "message", "request_id",
    "detail" | "details"}}``; the ``wrong_region`` answer also carries ``code`` and ``region``
    at the top level."""
    code = f"http_{status}"
    message = reason or f"HTTP {status}"
    extra: dict[str, Any] = {}
    try:
        body = json.loads(text)
    except ValueError:
        body = None
    if isinstance(body, dict):
        err = body.get("error") if isinstance(body.get("error"), dict) else body
        assert isinstance(err, dict)
        if isinstance(err.get("code"), str):
            code = err["code"]
        elif isinstance(body.get("code"), str):
            code = body["code"]
        if isinstance(err.get("message"), str):
            message = err["message"]
        if isinstance(err.get("request_id"), str):
            extra["request_id"] = err["request_id"]
        for key in ("detail", "details"):
            if err.get(key) is not None:
                extra["details"] = err[key]
        region = err.get("region") or body.get("region") or body.get("home_region")
        if isinstance(region, str):
            extra["region"] = region
    extra.setdefault("request_id", headers.get("X-Request-ID"))
    extra["retry_after"] = retry_after_seconds(headers.get("Retry-After"))
    return error_for(status, code, message, **extra)


def retry_after_seconds(value: Optional[str], now: Optional[float] = None) -> float:
    """Retry-After in seconds (seconds or an HTTP date); 0 when absent or unreadable."""
    if not value:
        return 0.0
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        at = email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, at - (time.time() if now is None else now))
