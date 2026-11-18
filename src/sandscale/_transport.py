# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""The HTTP transport every service shares: auth, regions, retries and error mapping."""

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import time
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping, Optional, Union
from urllib.parse import urlsplit

import httpx

from ._version import VERSION
from .errors import (
    APIConnectionError,
    ConfigurationError,
    EntitlementError,
    KillSwitchError,
    RegionError,
    SandscaleError,
    parse_error,
)

DEFAULT_BASE_URL = "https://api.sandscale.dev"
#: Sandscale's regional APIs ; api.sandscale.dev routes to the request's region,
#: US by default.
SANDSCALE_REGION_URLS: Mapping[str, str] = MappingProxyType(
    {"us": "https://api.us.sandscale.dev", "eu": "https://api.eu.sandscale.dev"}
)
_FRONT_DOOR_HOST = "api.sandscale.dev"


def _sandscale_region(region: str) -> str:
    """A Sandscale region's name: ``us1`` and ``us`` are the same region."""
    return re.sub(r"\d+$", "", region.lower())
TokenSource = Union[str, Callable[[], str]]

_SAFE_METHODS = {"GET", "HEAD"}
_RETRY_STATUSES = {429, 502, 503, 504}
_REGION_LIST_TTL = 60.0
_MAX_BACKOFF = 8.0
_MAX_RETRY_AFTER = 60.0


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_url(raw: str, source: str) -> str:
    """Validates an API origin: https, or http only to loopback; no credentials, query or fragment."""
    parts = urlsplit(raw)
    if not parts.scheme or not parts.hostname:
        raise ConfigurationError(f"{source} is not an absolute URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigurationError(f"{source} must not carry credentials, a query or a fragment")
    if not (parts.scheme == "https" or (parts.scheme == "http" and _is_loopback(parts.hostname))):
        raise ConfigurationError(f"{source} must use https (http only to a loopback host)")
    return raw.rstrip("/")


class Transport:
    """Sends the SDK's requests. Built by :class:`sandscale.Sandscale`."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        token: Optional[TokenSource] = None,
        base_url: Optional[str] = None,
        org_id: Optional[str] = None,
        region: Optional[str] = None,
        region_urls: Optional[Mapping[str, str]] = None,
        timeout: float = 60.0,
        max_retries: int = 2,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        if api_key is None and token is None:
            api_key = os.environ.get("SANDSCALE_API_KEY") or None
        if api_key is not None and token is not None:
            raise ConfigurationError("give api_key or token, not both")
        credential = api_key if api_key is not None else token
        if credential is None or (isinstance(credential, str) and not credential.strip()):
            raise ConfigurationError("no credential: pass api_key or token, or set SANDSCALE_API_KEY")
        self._credential: TokenSource = credential
        self.base_url = check_url(base_url or os.environ.get("SANDSCALE_BASE_URL") or DEFAULT_BASE_URL, "base_url")
        #: True when the base URL is Sandscale's front door, whose regions are fixed hosts.
        self._sandscale = urlsplit(self.base_url).hostname == _FRONT_DOOR_HOST
        self.org_id = org_id or os.environ.get("SANDSCALE_ORG_ID") or None
        self.region = region
        self._region_urls = {k: check_url(v, f"region_urls[{k!r}]") for k, v in (region_urls or {}).items()}
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        # Redirects are refused so a credential never follows one.
        self._http = http_client or httpx.Client(follow_redirects=False)
        self._regions: Optional[tuple[float, list[dict[str, Any]]]] = None
        #: Overridable for tests.
        self.sleep: Callable[[float], None] = time.sleep

    def close(self) -> None:
        self._http.close()

    def require_org(self) -> str:
        if not self.org_id:
            raise ConfigurationError("this call needs an organization: pass org_id or set SANDSCALE_ORG_ID")
        return self.org_id

    def region_of(self, region: Optional[str]) -> Optional[str]:
        return region if region is not None else self.region

    def origin_for(self, region: Optional[str]) -> str:
        """The API origin of a region. Explicit ``region_urls`` win. On Sandscale (the front door
        api.sandscale.dev) a region is one of Sandscale's regional APIs, ``us`` and ``eu``
        (a region id such as ``us1`` names the same), with no lookup. Against
        another base URL (a self-hosted Keystone) the region is looked up in the server's public
        region list (GET /api/v1/regions): an exact id, or the one live region whose id is the
        name followed by digits."""
        if region is None:
            return self.base_url
        if region in self._region_urls:
            return self._region_urls[region]
        if self._sandscale:
            url = SANDSCALE_REGION_URLS.get(_sandscale_region(region))
            if url is None:
                names = " or ".join(SANDSCALE_REGION_URLS)
                raise RegionError(0, "region_unknown", f"Sandscale has no region {region}; use {names}")
            return url
        entries = self._region_list()
        matches = [r for r in entries if r["id"] == region]
        if not matches:
            pattern = re.compile(re.escape(region) + r"\d+")
            matches = [r for r in entries if pattern.fullmatch(r["id"])]
        if not matches:
            raise RegionError(0, "region_unknown", f"the server lists no region {region}")
        if len(matches) > 1:
            names = ", ".join(r["id"] for r in matches)
            raise RegionError(0, "region_ambiguous", f"region {region} matches {names}; name one")
        entry = matches[0]
        if entry.get("status") != "live" or not entry.get("api_url"):
            raise RegionError(
                0,
                "region_unavailable",
                f"region {entry['id']} is not available now ({entry.get('status') or 'no API URL'})",
                region=entry["id"],
            )
        return check_url(str(entry["api_url"]), f"the API URL of region {entry['id']}")

    def live_regions(self) -> list[str]:
        """The live regions, for calls that list every region. On Sandscale: the Sandscale
        regions the front door's region list reports live (``us1`` is ``us``)."""
        if self._region_urls:
            return list(self._region_urls)
        live = [r["id"] for r in self._region_list() if r.get("status") == "live" and (self._sandscale or r.get("api_url"))]
        if not self._sandscale:
            return live
        out: list[str] = []
        for name in map(_sandscale_region, live):
            if name in SANDSCALE_REGION_URLS and name not in out:
                out.append(name)
        return out

    def _region_list(self) -> list[dict[str, Any]]:
        if self._regions is not None and time.monotonic() - self._regions[0] < _REGION_LIST_TTL:
            return self._regions[1]
        # The region list is public: no credential is sent.
        resp = self._send("GET", f"{self.base_url}/api/v1/regions", {"Accept": "application/json"}, None, None)
        if resp.status_code >= 400:
            raise parse_error(resp.status_code, resp.reason_phrase, resp.text, resp.headers)
        body = resp.json()
        entries = [r for r in body.get("regions") or [] if isinstance(r, dict) and isinstance(r.get("id"), str)]
        self._regions = (time.monotonic(), entries)
        return entries

    def _authorization(self) -> str:
        value = self._credential() if callable(self._credential) else self._credential
        if not value or not value.strip():
            raise ConfigurationError("the token function returned an empty token")
        return f"Bearer {value}"

    def request(
        self,
        method: str,
        path: str,
        *,
        region: Optional[str] = None,
        query: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Sends one request and returns the parsed JSON (None for an empty body)."""
        resp = self._call(method, path, region=region, query=query, json_body=json_body, timeout=timeout)
        return resp.json() if resp.content else None

    def request_bytes(self, method: str, path: str, *, region: Optional[str] = None) -> bytes:
        """Sends one request and returns the response body unparsed (a download)."""
        return self._call(method, path, region=region, query=None, json_body=None, timeout=None).content

    def stream_lines(self, path: str, *, region: Optional[str], query: Mapping[str, Any]) -> Iterator[str]:
        """Opens a Server-Sent Events stream and yields its lines."""
        origin = self.origin_for(self.region_of(region))
        params = {k: v for k, v in query.items() if v is not None}
        headers = self._headers("text/event-stream")
        try:
            with self._http.stream(
                "GET", f"{origin}{path}", params=params, headers=headers, timeout=httpx.Timeout(self._timeout, read=None)
            ) as resp:
                if resp.status_code >= 400:
                    resp.read()
                    raise parse_error(resp.status_code, resp.reason_phrase, resp.text, resp.headers)
                yield from resp.iter_lines()
        except httpx.TransportError as e:
            raise APIConnectionError(f"GET {path} failed: {type(e).__name__}") from e

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {
            "Authorization": self._authorization(),
            "Accept": accept,
            "User-Agent": f"sandscale-sdk-python/{VERSION}",
        }
        if self.org_id:
            headers["X-Org-ID"] = self.org_id
        return headers

    def _call(
        self,
        method: str,
        path: str,
        *,
        region: Optional[str],
        query: Optional[Mapping[str, Any]],
        json_body: Any,
        timeout: Optional[float],
    ) -> httpx.Response:
        url = f"{self.origin_for(self.region_of(region))}{path}"
        params = {k: v for k, v in (query or {}).items() if v is not None}
        headers = self._headers("application/json")
        content: Optional[bytes] = None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            content = json.dumps(json_body).encode()
        retries = self._max_retries if method in _SAFE_METHODS else 0
        attempt = 0
        while True:
            error: SandscaleError
            try:
                resp = self._send(method, url, headers, content, timeout, params)
                if resp.status_code < 400:
                    return resp
                error = parse_error(resp.status_code, resp.reason_phrase, resp.text, resp.headers)
                if resp.status_code not in _RETRY_STATUSES or not _retryable(error):
                    raise error
            except APIConnectionError as e:
                error = e
            if attempt >= retries:
                raise error
            if error.retry_after > 0:
                wait = min(error.retry_after, _MAX_RETRY_AFTER)
            else:
                wait = random.uniform(0, min(_MAX_BACKOFF, 0.5 * 2**attempt))
            self.sleep(wait)
            attempt += 1

    def _send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        content: Optional[bytes],
        timeout: Optional[float],
        params: Optional[Mapping[str, Any]] = None,
    ) -> httpx.Response:
        try:
            return self._http.request(
                method, url, headers=headers, content=content, params=params, timeout=timeout or self._timeout
            )
        except httpx.TimeoutException as e:
            raise APIConnectionError(f"{method} {urlsplit(url).path} timed out") from e
        except httpx.TransportError as e:
            raise APIConnectionError(f"{method} {urlsplit(url).path} failed: {type(e).__name__}") from e


def _retryable(error: SandscaleError) -> bool:
    """A kill switch, an entitlement or a region refusal never changes by retrying."""
    return not isinstance(error, (KillSwitchError, EntitlementError, RegionError))


def seg(value: str) -> str:
    """One path segment, escaped."""
    from urllib.parse import quote

    if not value:
        raise ConfigurationError("an id is empty")
    return quote(value, safe="")
