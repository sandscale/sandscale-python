# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Organization-level sandbox services: snapshots, templates, policy, webhooks and run traces."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from typing import Any, Mapping, Optional, Sequence, Union

from ._services import list_across_regions
from ._transport import Transport, seg
from .admin_models import (
    CreatedWebhook,
    SandboxPolicy,
    SnapshotList,
    SnapshotUsage,
    Template,
    TemplateBuildStatus,
    Trace,
    TraceExport,
    TraceExportTest,
    TraceSummary,
    Webhook,
)
from .models import ListResult, RegionPage, Snapshot

Raw = dict[str, Any]


def _body(fields: Mapping[str, Any]) -> Raw:
    return {k: v for k, v in fields.items() if v is not None}


class Snapshots:
    """The organization's sandbox snapshots (take one with ``sandboxes.snapshot``)."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def list(self, *, limit: Optional[int] = None, region: Optional[str] = None) -> SnapshotList:
        """The snapshots you may see, with the snapshot quota used (summed over the regions read)."""
        usage = SnapshotUsage()

        def one(r: Optional[str]) -> tuple[list[Snapshot], RegionPage]:
            raw = self._t.request("GET", "/api/v1/sandbox/snapshots", region=r, query={"limit": limit})
            u = raw.get("usage") or {}
            usage.count += int(u.get("count") or 0)
            usage.bytes += int(u.get("bytes") or 0)
            return [Snapshot.from_raw(s, r) for s in raw.get("snapshots") or []], RegionPage(region=r)

        merged = list_across_regions(self._t, region, one)
        return SnapshotList(data=merged.data, pages=merged.pages, usage=usage)

    def get(self, snapshot_id: str, *, region: Optional[str] = None) -> Snapshot:
        raw = self._t.request("GET", f"/api/v1/sandbox/snapshots/{seg(snapshot_id)}", region=region)
        return Snapshot.from_raw(raw, self._t.region_of(region))

    def delete(self, snapshot_id: str, *, region: Optional[str] = None) -> None:
        """Deletes the snapshot and its stored copy; sandboxes started from it keep running."""
        self._t.request("DELETE", f"/api/v1/sandbox/snapshots/{seg(snapshot_id)}", region=region)


class Templates:
    def __init__(self, t: Transport) -> None:
        self._t = t

    def create(
        self,
        *,
        name: str,
        version: Optional[str] = None,
        image: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        disk_mb: Optional[int] = None,
        memory_mb: Optional[int] = None,
        cpu_count: Optional[int] = None,
        region: Optional[str] = None,
    ) -> Template:
        """Creates a template from an OCI image pinned by digest (``name@sha256:...``) or a snapshot."""
        body = _body(
            {
                "name": name,
                "version": version,
                "image": image,
                "snapshot_id": snapshot_id,
                "disk_size_mb": disk_mb,
                "mem_size_mb": memory_mb,
                "cpu_count": cpu_count,
            }
        )
        raw = self._t.request("POST", "/api/v1/sandbox/templates", region=region, json_body=body)
        return Template.from_raw(raw, self._t.region_of(region))

    def list(self, *, region: Optional[str] = None) -> ListResult[Template]:
        """The organization's templates and the built-in ones, of one region or of every live region."""

        def one(r: Optional[str]) -> tuple[list[Template], RegionPage]:
            raw = self._t.request("GET", "/api/v1/sandbox/templates", region=r)
            page = RegionPage(region=r, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"))
            return [Template.from_raw(x, r) for x in raw.get("data") or []], page

        return list_across_regions(self._t, region, one)

    def get(self, template_id: str, *, region: Optional[str] = None) -> Template:
        raw = self._t.request("GET", f"/api/v1/sandbox/templates/{seg(template_id)}", region=region)
        return Template.from_raw(raw, self._t.region_of(region))

    def delete(self, template_id: str, *, region: Optional[str] = None) -> None:
        self._t.request("DELETE", f"/api/v1/sandbox/templates/{seg(template_id)}", region=region)

    def build_status(self, template_id: str, *, region: Optional[str] = None) -> TemplateBuildStatus:
        raw = self._t.request("GET", f"/api/v1/sandbox/templates/{seg(template_id)}/build-status", region=region)
        return TemplateBuildStatus(status=str(raw.get("status") or ""), progress_percent=int(raw.get("progress_percent") or 0))


class Policy:
    """The organization's sandbox policy."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def get(self, *, region: Optional[str] = None) -> SandboxPolicy:
        raw = self._t.request("GET", "/api/v1/sandbox/policy", region=region)
        return SandboxPolicy.from_raw(raw, self._t.region_of(region))

    def set(
        self,
        *,
        max_concurrent: Optional[int] = None,
        max_exec_time_seconds: Optional[int] = None,
        max_memory_mb: Optional[int] = None,
        max_cpu: Optional[int] = None,
        max_disk_mb: Optional[int] = None,
        max_workspaces_per_user: Optional[int] = None,
        max_cpu_cores_per_user: Optional[int] = None,
        max_memory_gb_per_user: Optional[int] = None,
        egress_allowlist: Optional[Sequence[str]] = None,
        allowed_providers: Optional[Sequence[str]] = None,
        egress_presets: Optional[Sequence[str]] = None,
        hibernation: Optional[str] = None,
        region: Optional[str] = None,
    ) -> SandboxPolicy:
        """Changes the members you name; the rest keep their values. ``hibernation_mode`` is a
        typed seam: sent as ``hibernation_mode`` only when set, and a server without hibernation
        refuses it."""
        body = _body(
            {
                "max_concurrent": max_concurrent,
                "max_exec_time_sec": max_exec_time_seconds,
                "max_mem_mb": max_memory_mb,
                "max_cpu": max_cpu,
                "max_disk_mb": max_disk_mb,
                "max_workspaces_per_user": max_workspaces_per_user,
                "max_cpu_cores_per_user": max_cpu_cores_per_user,
                "max_memory_gb_per_user": max_memory_gb_per_user,
                "egress_allowlist": list(egress_allowlist) if egress_allowlist is not None else None,
                "allowed_providers": list(allowed_providers) if allowed_providers is not None else None,
                "egress_presets": list(egress_presets) if egress_presets is not None else None,
                "hibernation": hibernation,
            }
        )
        raw = self._t.request("PUT", "/api/v1/sandbox/policy", region=region, json_body=body)
        return SandboxPolicy.from_raw(raw, self._t.region_of(region))


def verify_webhook_signature(signature: Optional[str], body: Union[bytes, str], secret: str) -> bool:
    """True when ``signature`` (the ``X-Keystone-Signature`` header, ``sha256=<hex>``) is the
    HMAC-SHA256 of the raw request ``body`` under the webhook's secret. Pass the body exactly as
    received, before any JSON parsing. The comparison is constant time; a missing or malformed
    header is False. (Current signing carries no timestamp.)"""
    if not signature or not secret or not signature.startswith("sha256="):
        return False
    given = signature[len("sha256=") :].strip().lower()
    data = body.encode() if isinstance(body, str) else body
    expected = hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(given.encode(), expected.encode())


class Webhooks:
    """Webhook endpoints for sandbox events."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    verify = staticmethod(verify_webhook_signature)

    def list(self, *, region: Optional[str] = None) -> list[Webhook]:
        raw = self._t.request("GET", "/api/v1/sandbox/webhooks", region=region)
        r = self._t.region_of(region)
        return [Webhook.from_raw(w, r) for w in raw.get("webhooks") or []]

    def create(
        self,
        *,
        url: str,
        events: Optional[Sequence[str]] = None,
        secret: Optional[str] = None,
        region: Optional[str] = None,
    ) -> CreatedWebhook:
        """Registers an endpoint. The signing secret is shown once, on the returned object."""
        body = _body({"url": url, "events": list(events) if events is not None else None, "secret": secret})
        raw = self._t.request("POST", "/api/v1/sandbox/webhooks", region=region, json_body=body)
        return CreatedWebhook.from_raw(raw, self._t.region_of(region))

    def delete(self, webhook_id: str, *, region: Optional[str] = None) -> None:
        self._t.request("DELETE", f"/api/v1/sandbox/webhooks/{seg(webhook_id)}", region=region)


def _iso(value: Union[datetime, str, None]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else value


class Traces:
    """Run traces and the OpenTelemetry export."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def list(
        self,
        *,
        sandbox_id: Optional[str] = None,
        from_: Union[datetime, str, None] = None,
        to: Union[datetime, str, None] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        region: Optional[str] = None,
    ) -> ListResult[TraceSummary]:
        def one(r: Optional[str]) -> tuple[list[TraceSummary], RegionPage]:
            query = {"sandbox_id": sandbox_id, "from": _iso(from_), "to": _iso(to), "limit": limit, "cursor": cursor}
            raw = self._t.request("GET", "/api/v1/sandbox/traces", region=r, query=query)
            page = RegionPage(region=r, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"))
            return [TraceSummary.from_raw(x, r) for x in raw.get("data") or []], page

        return list_across_regions(self._t, region, one)

    def get(self, trace_id: str, *, region: Optional[str] = None) -> Trace:
        raw = self._t.request("GET", f"/api/v1/sandbox/traces/{seg(trace_id)}", region=region)
        return Trace.from_raw(raw, self._t.region_of(region))

    def get_export(self, *, region: Optional[str] = None) -> TraceExport:
        raw = self._t.request("GET", "/api/v1/sandbox/trace-export", region=region)
        return TraceExport.from_raw(raw, self._t.region_of(region))

    def set_export(
        self,
        *,
        protocol: str,
        endpoint: str,
        headers: Optional[Mapping[str, str]] = None,
        enabled: Optional[bool] = None,
        region: Optional[str] = None,
    ) -> TraceExport:
        """Creates or replaces the export. ``headers`` are stored in Keystone Vault and never answered;
        omit them to keep the stored ones, ``{}`` removes them."""
        body = _body({"protocol": protocol, "endpoint": endpoint, "headers": dict(headers) if headers is not None else None, "enabled": enabled})
        raw = self._t.request("PUT", "/api/v1/sandbox/trace-export", region=region, json_body=body)
        return TraceExport.from_raw(raw, self._t.region_of(region))

    def delete_export(self, *, region: Optional[str] = None) -> None:
        self._t.request("DELETE", "/api/v1/sandbox/trace-export", region=region)

    def test_export(self, *, region: Optional[str] = None) -> TraceExportTest:
        raw = self._t.request("POST", "/api/v1/sandbox/trace-export/test", region=region)
        return TraceExportTest(ok=raw.get("ok") is True, trace_id=raw.get("trace_id") or None, error=raw.get("error") or None)
