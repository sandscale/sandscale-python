# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Models of the sandbox administration, object storage, compute and account services.

Every model keeps the server's full answer in ``raw`` (without any secret) and the ``region`` it
was read from. A secret the server shows once (a webhook signing secret, a secret access key, an
API key) is a field with ``repr=False`` and ``compare=False``: it never appears in ``repr``, in
logs or in ``raw``; read it by name, once, and store it where it belongs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional

from .models import ListResult, Snapshot, parse_time

Raw = dict[str, Any]


def _s(raw: Mapping[str, Any], key: str) -> Optional[str]:
    v = raw.get(key)
    return v if isinstance(v, str) and v else None


def _i(raw: Mapping[str, Any], key: str, default: int = 0) -> int:
    v = raw.get(key)
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else default


def _f(raw: Mapping[str, Any], key: str) -> float:
    v = raw.get(key)
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def _oi(raw: Mapping[str, Any], key: str) -> Optional[int]:
    v = raw.get(key)
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _b(raw: Mapping[str, Any], key: str) -> bool:
    return raw.get(key) is True


def _l(raw: Mapping[str, Any], key: str) -> list[str]:
    v = raw.get(key)
    return [str(x) for x in v] if isinstance(v, list) else []


def _d(raw: Mapping[str, Any], key: str) -> dict[str, str]:
    v = raw.get(key)
    return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}


def _obj(raw: Mapping[str, Any], key: str) -> Raw:
    v = raw.get(key)
    return v if isinstance(v, dict) else {}


def without(raw: Mapping[str, Any], *names: str) -> Raw:
    """A shallow copy of a raw answer without the named secret members."""
    return {k: v for k, v in raw.items() if k not in names}


# --- sandbox: ports, preview links, SSH ----------------------------------------------------


@dataclass(kw_only=True)
class PortExposure:
    id: str
    instance_id: str = ""
    port: int = 0
    protocol: str = "tcp"
    #: ``open``, ``closed`` or ``expired``.
    status: str = ""
    created_by: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    close_reason: Optional[str] = None
    #: The WebSocket route that carries one TCP connection (on the region's API origin).
    connect_path: str = ""
    subprotocol: str = ""
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "PortExposure":
        return cls(
            id=str(raw.get("id")),
            instance_id=str(raw.get("instance_id") or ""),
            port=_i(raw, "port"),
            protocol=str(raw.get("protocol") or "tcp"),
            status=str(raw.get("status") or ""),
            created_by=str(raw.get("created_by") or ""),
            created_at=parse_time(raw.get("created_at")),
            expires_at=parse_time(raw.get("expires_at")),
            closed_at=parse_time(raw.get("closed_at")),
            close_reason=_s(raw, "close_reason"),
            connect_path=str(raw.get("connect_path") or ""),
            subprotocol=str(raw.get("subprotocol") or ""),
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class PreviewLink:
    id: str
    instance_id: str = ""
    exposure_id: str = ""
    port: int = 0
    #: ``team`` or ``public``.
    visibility: str = ""
    url: str = ""
    #: ``active``, ``expired`` or ``revoked``.
    status: str = ""
    created_by: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None
    abuse_rule: Optional[str] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "PreviewLink":
        return cls(
            id=str(raw.get("id")),
            instance_id=str(raw.get("instance_id") or ""),
            exposure_id=str(raw.get("exposure_id") or ""),
            port=_i(raw, "port"),
            visibility=str(raw.get("visibility") or ""),
            url=str(raw.get("url") or ""),
            status=str(raw.get("status") or ""),
            created_by=str(raw.get("created_by") or ""),
            created_at=parse_time(raw.get("created_at")),
            expires_at=parse_time(raw.get("expires_at")),
            revoked_at=parse_time(raw.get("revoked_at")),
            revoke_reason=_s(raw, "revoke_reason"),
            abuse_rule=_s(raw, "abuse_rule"),
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class SandboxSshInfo:
    """How to connect to a sandbox over SSH: the host key to trust and the route to connect through."""

    host: str = ""
    user: str = ""
    known_hosts: str = ""
    host_key_sha256: str = ""
    certificate_path: str = ""
    connect_path: str = ""
    subprotocol: str = ""
    cert_ttl_seconds: int = 0
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "SandboxSshInfo":
        return cls(**_ssh_fields(raw, region))


def _ssh_fields(raw: Raw, region: Optional[str]) -> dict[str, Any]:
    return {
        "host": str(raw.get("host") or ""),
        "user": str(raw.get("user") or ""),
        "known_hosts": str(raw.get("known_hosts") or ""),
        "host_key_sha256": str(raw.get("host_key_sha256") or ""),
        "certificate_path": str(raw.get("certificate_path") or ""),
        "connect_path": str(raw.get("connect_path") or ""),
        "subprotocol": str(raw.get("subprotocol") or ""),
        "cert_ttl_seconds": _i(raw, "cert_ttl_seconds"),
        "region": region,
        "raw": raw,
    }


@dataclass(kw_only=True)
class SandboxSshCertificate(SandboxSshInfo):
    """The connection details with a short-lived certificate for your public key."""

    certificate: str = ""
    serial: str = ""
    key_id: str = ""
    valid_before: Optional[datetime] = None

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "SandboxSshCertificate":
        return cls(
            **_ssh_fields(raw, region),
            certificate=str(raw.get("certificate") or ""),
            serial=str(raw.get("serial") or ""),
            key_id=str(raw.get("key_id") or ""),
            valid_before=parse_time(raw.get("valid_before")),
        )


# --- snapshots, templates, policy ------------------------------------------------------------


@dataclass
class SnapshotUsage:
    count: int = 0
    bytes: int = 0


@dataclass
class SnapshotList(ListResult[Snapshot]):
    """The organization's snapshots with the snapshot quota used (summed over the regions read)."""

    usage: SnapshotUsage = field(default_factory=SnapshotUsage)


@dataclass(kw_only=True)
class Template:
    id: str
    name: str = ""
    version: str = ""
    #: ``building``, ``ready`` or ``failed``.
    status: str = ""
    disk_size_mb: Optional[int] = None
    mem_size_mb: Optional[int] = None
    cpu_count: Optional[int] = None
    image: Optional[str] = None
    snapshot_id: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Template":
        return cls(
            id=str(raw.get("id")),
            name=str(raw.get("name") or ""),
            version=str(raw.get("version") or ""),
            status=str(raw.get("status") or ""),
            disk_size_mb=_oi(raw, "disk_size_mb"),
            mem_size_mb=_oi(raw, "mem_size_mb"),
            cpu_count=_oi(raw, "cpu_count"),
            image=_s(raw, "image"),
            snapshot_id=_s(raw, "snapshot_id"),
            created_by=_s(raw, "created_by"),
            created_at=parse_time(raw.get("created_at")),
            region=region,
            raw=raw,
        )


@dataclass
class TemplateBuildStatus:
    #: ``building``, ``ready`` or ``failed``.
    status: str
    progress_percent: int = 0


@dataclass(kw_only=True)
class SandboxPolicy:
    max_concurrent: int = 0
    max_exec_time_seconds: int = 0
    max_memory_mb: int = 0
    max_cpu: int = 0
    max_disk_mb: Optional[int] = None
    max_workspaces_per_user: Optional[int] = None
    max_cpu_cores_per_user: Optional[int] = None
    max_memory_gb_per_user: Optional[int] = None
    egress_allowlist: list[str] = field(default_factory=list)
    allowed_providers: list[str] = field(default_factory=list)
    #: Package registry presets for ``allowlist`` sandboxes (``npm``, ``pypi``, ``go``, ``crates``).
    egress_presets: list[str] = field(default_factory=list)
    #: Hibernation mode, when the server sends ``hibernation_mode`` (not on every deployment).
    hibernation: Optional[str] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "SandboxPolicy":
        return cls(
            max_concurrent=_i(raw, "max_concurrent"),
            max_exec_time_seconds=_i(raw, "max_exec_time_sec"),
            max_memory_mb=_i(raw, "max_mem_mb"),
            max_cpu=_i(raw, "max_cpu"),
            max_disk_mb=_oi(raw, "max_disk_mb"),
            max_workspaces_per_user=_oi(raw, "max_workspaces_per_user"),
            max_cpu_cores_per_user=_oi(raw, "max_cpu_cores_per_user"),
            max_memory_gb_per_user=_oi(raw, "max_memory_gb_per_user"),
            egress_allowlist=_l(raw, "egress_allowlist"),
            allowed_providers=_l(raw, "allowed_providers"),
            egress_presets=_l(raw, "egress_presets"),
            hibernation=_s(raw, "hibernation"),
            region=region,
            raw=raw,
        )


# --- webhooks ----------------------------------------------------------------------------------


@dataclass(kw_only=True)
class Webhook:
    id: str
    url: str = ""
    events: list[str] = field(default_factory=list)
    active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Webhook":
        return cls(**_webhook_fields(raw, region))


def _webhook_fields(raw: Raw, region: Optional[str]) -> dict[str, Any]:
    return {
        "id": str(raw.get("id")),
        "url": str(raw.get("url") or ""),
        "events": _l(raw, "events"),
        "active": raw.get("active") is not False,
        "created_at": parse_time(raw.get("created_at")),
        "updated_at": parse_time(raw.get("updated_at")),
        "region": region,
        "raw": without(raw, "secret"),
    }


@dataclass(kw_only=True)
class CreatedWebhook(Webhook):
    """A webhook as created. ``secret`` is the signing secret the server shows once: not in
    ``repr``, comparisons or ``raw``."""

    secret: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "CreatedWebhook":
        return cls(**_webhook_fields(raw, region), secret=str(raw.get("secret") or ""))


# --- run traces ---------------------------------------------------------------------------------


@dataclass(kw_only=True)
class TraceSummary:
    trace_id: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: int = 0
    spans: int = 0
    errors: int = 0
    sandboxes: list[str] = field(default_factory=list)
    vcpu_hours: float = 0.0
    usd: float = 0.0
    #: ``ok`` or ``error``.
    status: str = ""
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "TraceSummary":
        return cls(**_trace_fields(raw, region))


def _trace_fields(raw: Raw, region: Optional[str]) -> dict[str, Any]:
    return {
        "trace_id": str(raw.get("trace_id") or ""),
        "start_time": parse_time(raw.get("start_time")),
        "end_time": parse_time(raw.get("end_time")),
        "duration_ms": _i(raw, "duration_ms"),
        "spans": _i(raw, "spans"),
        "errors": _i(raw, "errors"),
        "sandboxes": _l(raw, "sandboxes"),
        "vcpu_hours": _f(raw, "vcpu_hours"),
        "usd": _f(raw, "usd"),
        "status": str(raw.get("status") or ""),
        "region": region,
        "raw": raw,
    }


@dataclass(kw_only=True)
class TraceCommand:
    argv: list[str] = field(default_factory=list)
    run_id: Optional[str] = None
    exit_code: Optional[int] = None
    output_bytes: Optional[int] = None
    oom_killed: bool = False
    timed_out: bool = False


@dataclass(kw_only=True)
class TraceFile:
    path: str = ""
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None


@dataclass(kw_only=True)
class TraceBox:
    sandbox_id: Optional[str] = None
    worker_id: Optional[str] = None
    runtime: Optional[str] = None
    isolation: Optional[str] = None
    vcpu: Optional[int] = None
    memory_mb: Optional[int] = None
    region: Optional[str] = None


@dataclass(kw_only=True)
class TraceCost:
    vcpu_hours: float = 0.0
    usd: float = 0.0


@dataclass(kw_only=True)
class TraceSpan:
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: Optional[str] = None
    #: ``command`` or ``file_write``.
    kind: str = ""
    name: str = ""
    #: ``ok``, ``error``, ``withheld`` or ``unfinished``.
    status: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: int = 0
    user_id: Optional[str] = None
    tool_identity: Optional[str] = None
    audit_entry_id: str = ""
    command: Optional[TraceCommand] = None
    files: list[TraceFile] = field(default_factory=list)
    box: TraceBox = field(default_factory=TraceBox)
    cost: TraceCost = field(default_factory=TraceCost)
    dlp_rules: list[str] = field(default_factory=list)
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "TraceSpan":
        cmd = _obj(raw, "command")
        box = _obj(raw, "box")
        cost = _obj(raw, "cost")
        return cls(
            trace_id=str(raw.get("trace_id") or ""),
            span_id=str(raw.get("span_id") or ""),
            parent_span_id=_s(raw, "parent_span_id"),
            kind=str(raw.get("kind") or ""),
            name=str(raw.get("name") or ""),
            status=str(raw.get("status") or ""),
            start_time=parse_time(raw.get("start_time")),
            end_time=parse_time(raw.get("end_time")),
            duration_ms=_i(raw, "duration_ms"),
            user_id=_s(raw, "user_id"),
            tool_identity=_s(raw, "tool_identity"),
            audit_entry_id=str(raw.get("audit_entry_id") or ""),
            command=TraceCommand(
                argv=_l(cmd, "argv"),
                run_id=_s(cmd, "run_id"),
                exit_code=_oi(cmd, "exit_code"),
                output_bytes=_oi(cmd, "output_bytes"),
                oom_killed=_b(cmd, "oom_killed"),
                timed_out=_b(cmd, "timed_out"),
            )
            if cmd
            else None,
            files=[
                TraceFile(path=str(f.get("path") or ""), sha256=_s(f, "sha256"), size_bytes=_oi(f, "size_bytes"))
                for f in raw.get("files") or []
                if isinstance(f, dict)
            ],
            box=TraceBox(
                sandbox_id=_s(box, "sandbox_id"),
                worker_id=_s(box, "worker_id"),
                runtime=_s(box, "runtime"),
                isolation=_s(box, "isolation"),
                vcpu=_oi(box, "vcpu"),
                memory_mb=_oi(box, "memory_mb"),
                region=_s(box, "region"),
            ),
            cost=TraceCost(vcpu_hours=_f(cost, "vcpu_hours"), usd=_f(cost, "usd")),
            dlp_rules=_l(raw, "dlp_rules"),
            raw=raw,
        )


@dataclass(kw_only=True)
class TraceEvent:
    id: str = ""
    ts: Optional[datetime] = None
    source: str = ""
    type: str = ""
    severity: str = ""


@dataclass(kw_only=True)
class Trace(TraceSummary):
    span_list: list[TraceSpan] = field(default_factory=list)
    #: Spans on sandboxes the caller may not use (left out).
    hidden_spans: int = 0
    truncated: bool = False
    events: list[TraceEvent] = field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Trace":
        return cls(
            **_trace_fields(raw, region),
            span_list=[TraceSpan.from_raw(s) for s in raw.get("span_list") or [] if isinstance(s, dict)],
            hidden_spans=_i(raw, "hidden_spans"),
            truncated=_b(raw, "truncated"),
            events=[
                TraceEvent(
                    id=str(e.get("id") or ""),
                    ts=parse_time(e.get("ts")),
                    source=str(e.get("source") or ""),
                    type=str(e.get("type") or ""),
                    severity=str(e.get("severity") or ""),
                )
                for e in raw.get("events") or []
                if isinstance(e, dict)
            ],
        )


@dataclass(kw_only=True)
class TraceExport:
    """The organization's OpenTelemetry export. Header names only: the values are never answered."""

    enabled: bool = False
    protocol: str = ""
    endpoint: str = ""
    header_names: list[str] = field(default_factory=list)
    #: ``active`` or ``degraded``.
    state: str = ""
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    last_export_at: Optional[datetime] = None
    next_attempt_at: Optional[datetime] = None
    exported_spans: int = 0
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "TraceExport":
        return cls(
            enabled=_b(raw, "enabled"),
            protocol=str(raw.get("protocol") or ""),
            endpoint=str(raw.get("endpoint") or ""),
            header_names=_l(raw, "header_names"),
            state=str(raw.get("state") or ""),
            consecutive_failures=_i(raw, "consecutive_failures"),
            last_error=_s(raw, "last_error"),
            last_export_at=parse_time(raw.get("last_export_at")),
            next_attempt_at=parse_time(raw.get("next_attempt_at")),
            exported_spans=_i(raw, "exported_spans"),
            updated_at=parse_time(raw.get("updated_at")),
            updated_by=_s(raw, "updated_by"),
            region=region,
            raw=raw,
        )


@dataclass
class TraceExportTest:
    ok: bool
    trace_id: Optional[str] = None
    #: A fixed reason, never a header value or a response body.
    error: Optional[str] = None


# --- object storage -------------------------------------------------------------------------------


@dataclass
class DefaultRetention:
    #: ``GOVERNANCE`` or ``COMPLIANCE``.
    mode: str
    days: int


@dataclass
class BucketEndpoints:
    path_style: str = ""
    signing_region: str = ""
    virtual_hosted: Optional[str] = None


@dataclass
class BucketUsage:
    keys: int = 0
    versions: int = 0
    bytes: int = 0
    uploads: int = 0
    reported_at: Optional[datetime] = None


@dataclass(kw_only=True)
class Bucket:
    name: str
    nrn: Optional[str] = None
    versioning: str = ""
    object_lock: bool = False
    default_retention: Optional[DefaultRetention] = None
    encryption: str = ""
    content_class: str = ""
    data_events: str = ""
    presign: bool = False
    allow_unsigned_payload: bool = False
    has_policy: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    endpoints: BucketEndpoints = field(default_factory=BucketEndpoints)
    usage: Optional[BucketUsage] = None
    deleting: bool = False
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Bucket":
        dr = _obj(raw, "DefaultRetention")
        ep = _obj(raw, "Endpoints")
        usage = _obj(raw, "Usage")
        return cls(
            name=str(raw.get("Name")),
            nrn=_s(raw, "Nrn"),
            versioning=str(raw.get("Versioning") or ""),
            object_lock=_b(raw, "ObjectLock"),
            default_retention=DefaultRetention(mode=str(dr.get("Mode") or ""), days=_i(dr, "Days")) if dr else None,
            encryption=str(raw.get("Encryption") or ""),
            content_class=str(raw.get("ContentClass") or ""),
            data_events=str(raw.get("DataEvents") or ""),
            presign=_b(raw, "Presign"),
            allow_unsigned_payload=_b(raw, "AllowUnsignedPayload"),
            has_policy=_b(raw, "HasPolicy"),
            tags=_d(raw, "Tags"),
            created_at=parse_time(raw.get("CreatedAt")),
            endpoints=BucketEndpoints(
                path_style=str(ep.get("PathStyle") or ""),
                signing_region=str(ep.get("SigningRegion") or ""),
                virtual_hosted=_s(ep, "VirtualHosted"),
            ),
            usage=BucketUsage(
                keys=_i(usage, "Keys"),
                versions=_i(usage, "Versions"),
                bytes=_i(usage, "Bytes"),
                uploads=_i(usage, "Uploads"),
                reported_at=parse_time(usage.get("ReportedAt")),
            )
            if usage
            else None,
            deleting=_b(raw, "Deleting"),
            region=region,
            raw=raw,
        )


@dataclass
class BucketList:
    buckets: list[Bucket] = field(default_factory=list)
    next_token: Optional[str] = None


@dataclass
class NoncurrentVersionExpiration:
    noncurrent_days: int
    newer_noncurrent_versions: Optional[int] = None


@dataclass(kw_only=True)
class LifecycleRule:
    id: str
    prefix: Optional[str] = None
    #: ``Enabled`` or ``Disabled``.
    status: str = "Enabled"
    #: Delete current versions this many days after creation.
    expiration_days: Optional[int] = None
    noncurrent_version_expiration: Optional[NoncurrentVersionExpiration] = None
    expired_object_delete_marker: Optional[bool] = None
    abort_incomplete_multipart_upload_days: Optional[int] = None

    def to_wire(self) -> Raw:
        out: Raw = {"ID": self.id, "Status": self.status}
        if self.prefix is not None:
            out["Prefix"] = self.prefix
        if self.expiration_days is not None:
            out["Expiration"] = {"Days": self.expiration_days}
        if self.noncurrent_version_expiration is not None:
            nc: Raw = {"NoncurrentDays": self.noncurrent_version_expiration.noncurrent_days}
            if self.noncurrent_version_expiration.newer_noncurrent_versions is not None:
                nc["NewerNoncurrentVersions"] = self.noncurrent_version_expiration.newer_noncurrent_versions
            out["NoncurrentVersionExpiration"] = nc
        if self.expired_object_delete_marker is not None:
            out["ExpiredObjectDeleteMarker"] = self.expired_object_delete_marker
        if self.abort_incomplete_multipart_upload_days is not None:
            out["AbortIncompleteMultipartUpload"] = {"DaysAfterInitiation": self.abort_incomplete_multipart_upload_days}
        return out

    @classmethod
    def from_raw(cls, raw: Raw) -> "LifecycleRule":
        exp = _obj(raw, "Expiration")
        nc = _obj(raw, "NoncurrentVersionExpiration")
        ab = _obj(raw, "AbortIncompleteMultipartUpload")
        return cls(
            id=str(raw.get("ID") or ""),
            prefix=_s(raw, "Prefix"),
            status=str(raw.get("Status") or ""),
            expiration_days=_oi(exp, "Days") if exp else None,
            noncurrent_version_expiration=NoncurrentVersionExpiration(
                noncurrent_days=_i(nc, "NoncurrentDays"), newer_noncurrent_versions=_oi(nc, "NewerNoncurrentVersions")
            )
            if nc
            else None,
            expired_object_delete_marker=raw.get("ExpiredObjectDeleteMarker") if isinstance(raw.get("ExpiredObjectDeleteMarker"), bool) else None,
            abort_incomplete_multipart_upload_days=_oi(ab, "DaysAfterInitiation") if ab else None,
        )


@dataclass(kw_only=True)
class AccessKey:
    access_key_id: str
    nrn: Optional[str] = None
    principal: str = ""
    description: str = ""
    #: ``Active`` or ``Inactive``.
    status: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    permissions: list[str] = field(default_factory=list)
    buckets: list[str] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "AccessKey":
        return cls(
            access_key_id=str(raw.get("AccessKeyId")),
            nrn=_s(raw, "Nrn"),
            principal=str(raw.get("Principal") or ""),
            description=str(raw.get("Description") or ""),
            status=str(raw.get("Status") or ""),
            created_at=parse_time(raw.get("CreatedAt")),
            expires_at=parse_time(raw.get("ExpiresAt")),
            permissions=_l(raw, "Permissions"),
            buckets=_l(raw, "Buckets"),
            prefixes=_l(raw, "Prefixes"),
            cidrs=_l(raw, "CIDRs"),
            region=region,
            raw=raw,
        )


@dataclass
class CreatedAccessKey:
    """An access key as created. ``secret_access_key`` is shown once: not in ``repr``."""

    access_key: AccessKey
    secret_access_key: str = field(default="", repr=False, compare=False)


@dataclass(kw_only=True)
class ObjectsLimits:
    enabled: bool = False
    reason: Optional[str] = None
    region: str = ""
    quotas: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, dict[str, Any]] = field(default_factory=dict)
    raw: Raw = field(default_factory=dict)


# --- workspaces ---------------------------------------------------------------------------------------


@dataclass(kw_only=True)
class OpenLink:
    ide: str = ""
    kind: str = ""
    url: str = ""
    ssh_host: Optional[str] = None
    folder: Optional[str] = None
    requires: list[str] = field(default_factory=list)
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "OpenLink":
        return cls(
            ide=str(raw.get("ide") or ""),
            kind=str(raw.get("kind") or ""),
            url=str(raw.get("url") or ""),
            ssh_host=_s(raw, "ssh_host"),
            folder=_s(raw, "folder"),
            requires=_l(raw, "requires"),
            raw=raw,
        )


@dataclass(kw_only=True)
class WorkspaceBackup:
    id: str
    workspace_id: Optional[str] = None
    type: str = ""
    status: str = ""
    size: int = 0
    checksum: Optional[str] = None
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "WorkspaceBackup":
        return cls(
            id=str(raw.get("id")),
            workspace_id=_s(raw, "workspace_id"),
            type=str(raw.get("type") or ""),
            status=str(raw.get("status") or ""),
            size=_i(raw, "size"),
            checksum=_s(raw, "checksum"),
            created_at=parse_time(raw.get("created_at")),
            completed_at=parse_time(raw.get("completed_at")),
            error=_s(raw, "error_msg"),
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class BackupVerification:
    backup_id: str = ""
    valid: bool = False
    checksum_match: bool = False
    errors: list[str] = field(default_factory=list)
    verified_at: Optional[datetime] = None


@dataclass(kw_only=True)
class WorkspaceApp:
    slug: str
    display_name: str = ""
    port: Optional[int] = None
    path: Optional[str] = None
    #: ``owner``, ``members``, ``org`` or ``public``.
    share: str = ""
    effective_share: str = ""
    health: Optional[str] = None
    origin: Optional[str] = None
    can_open: bool = False
    #: Why it cannot be opened now (``not_running``, ``not_authorized``, ``kill_switch``...).
    reason: Optional[str] = None
    message: Optional[str] = None
    share_levels: list[str] = field(default_factory=list)
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "WorkspaceApp":
        return cls(
            slug=str(raw.get("slug")),
            display_name=str(raw.get("display_name") or ""),
            port=_oi(raw, "port"),
            path=_s(raw, "path"),
            share=str(raw.get("share") or ""),
            effective_share=str(raw.get("effective_share") or ""),
            health=_s(raw, "health"),
            origin=_s(raw, "origin"),
            can_open=_b(raw, "can_open"),
            reason=_s(raw, "reason"),
            message=_s(raw, "message"),
            share_levels=_l(raw, "share_levels"),
            region=region,
            raw=raw,
        )


# --- build hosts and Agent Cloud ------------------------------------------------------------------------


@dataclass(kw_only=True)
class LeaseRun:
    id: str
    lease_id: str = ""
    argv: list[str] = field(default_factory=list)
    cwd: Optional[str] = None
    command: str = ""
    state: str = ""
    exit_code: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "LeaseRun":
        return cls(
            id=str(raw.get("id")),
            lease_id=str(raw.get("lease_id") or ""),
            argv=_l(raw, "argv"),
            cwd=_s(raw, "cwd"),
            command=str(raw.get("command") or ""),
            state=str(raw.get("state") or ""),
            exit_code=_oi(raw, "exit_code"),
            started_at=parse_time(raw.get("started_at")),
            finished_at=parse_time(raw.get("finished_at")),
            duration_ms=_oi(raw, "duration_ms"),
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class LeaseArtifact:
    id: str
    lease_id: str = ""
    run_id: Optional[str] = None
    name: str = ""
    size_bytes: int = 0
    sha256: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "LeaseArtifact":
        return cls(
            id=str(raw.get("id")),
            lease_id=str(raw.get("lease_id") or ""),
            run_id=_s(raw, "run_id"),
            name=str(raw.get("name") or ""),
            size_bytes=_i(raw, "size_bytes"),
            sha256=str(raw.get("sha256") or ""),
            created_at=parse_time(raw.get("created_at")),
            expires_at=parse_time(raw.get("expires_at")),
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class CacheEntry:
    id: str = ""
    cache: str = ""
    key: str = ""
    scope: str = ""
    size_bytes: int = 0
    sha256: str = ""
    lease_id: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


@dataclass(kw_only=True)
class CacheView:
    """A build cache with the entries you may restore (every entry for an administrator)."""

    name: str = ""
    scope: str = ""
    max_bytes: int = 0
    used_bytes: int = 0
    entries: list[CacheEntry] = field(default_factory=list)
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "CacheView":
        return cls(
            name=str(raw.get("name") or ""),
            scope=str(raw.get("scope") or ""),
            max_bytes=_i(raw, "max_bytes"),
            used_bytes=_i(raw, "used_bytes"),
            entries=[
                CacheEntry(
                    id=str(e.get("id") or ""),
                    cache=str(e.get("cache") or ""),
                    key=str(e.get("key") or ""),
                    scope=str(e.get("scope") or ""),
                    size_bytes=_i(e, "size_bytes"),
                    sha256=str(e.get("sha256") or ""),
                    lease_id=_s(e, "lease_id"),
                    created_at=parse_time(e.get("created_at")),
                    last_used_at=parse_time(e.get("last_used_at")),
                    expires_at=parse_time(e.get("expires_at")),
                )
                for e in raw.get("entries") or []
                if isinstance(e, dict)
            ],
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class AppShareResult:
    slug: str = ""
    share: str = ""
    effective_share: str = ""
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "AppShareResult":
        return cls(slug=str(raw.get("slug") or ""), share=str(raw.get("share") or ""), effective_share=str(raw.get("effective_share") or ""), raw=raw)


@dataclass(kw_only=True)
class LabHost:
    id: str
    name: str = ""
    status: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    pool_ids: list[str] = field(default_factory=list)
    max_leases: int = 0
    disabled: bool = False
    hostname: Optional[str] = None
    os: Optional[str] = None
    arch: Optional[str] = None
    health: Optional[str] = None
    last_seen_at: Optional[datetime] = None
    active_leases: int = 0
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "LabHost":
        return cls(
            id=str(raw.get("id")),
            name=str(raw.get("name") or ""),
            status=str(raw.get("status") or ""),
            labels=_d(raw, "labels"),
            pool_ids=_l(raw, "pool_ids"),
            max_leases=_i(raw, "max_leases"),
            disabled=_b(raw, "disabled"),
            hostname=_s(raw, "hostname"),
            os=_s(raw, "os"),
            arch=_s(raw, "arch"),
            health=_s(raw, "health"),
            last_seen_at=parse_time(raw.get("last_seen_at")),
            active_leases=_i(raw, "active_leases"),
            region=region,
            raw=raw,
        )


@dataclass(kw_only=True)
class AgentTask:
    id: str
    lead_grant_id: str = ""
    #: ``queued``, ``dispatching``, ``dispatched``, ``ended``, ``cancelled`` or ``refused``.
    state: str = ""
    engine: str = ""
    mode: Optional[str] = None
    repository: Optional[str] = None
    ref: Optional[str] = None
    target: Optional[str] = None
    lease_id: Optional[str] = None
    task_id: Optional[str] = None
    end_reason: Optional[str] = None
    attempts: Optional[int] = None
    created_at: Optional[datetime] = None
    dispatched_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    region: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "AgentTask":
        return cls(
            id=str(raw.get("id")),
            lead_grant_id=str(raw.get("lead_grant_id") or ""),
            state=str(raw.get("state") or ""),
            engine=str(raw.get("engine") or ""),
            mode=_s(raw, "mode"),
            repository=_s(raw, "repository"),
            ref=_s(raw, "ref"),
            target=_s(raw, "target"),
            lease_id=_s(raw, "lease_id"),
            task_id=_s(raw, "task_id"),
            end_reason=_s(raw, "end_reason"),
            attempts=_oi(raw, "attempts"),
            created_at=parse_time(raw.get("created_at")),
            dispatched_at=parse_time(raw.get("dispatched_at")),
            ended_at=parse_time(raw.get("ended_at")),
            region=region,
            raw=raw,
        )


# --- account --------------------------------------------------------------------------------------------


@dataclass(kw_only=True)
class PlanOffer:
    plan: str = ""
    name: str = ""
    monthly_minor: int = 0
    annual_monthly_minor: int = 0
    currency: str = ""
    per_seat: bool = False
    included_vcpu_hours: int = 0
    max_concurrent_boxes: int = 0
    max_vcpu_per_box: int = 0
    network_egress: bool = False
    max_lease_hours: int = 0
    object_storage_gb: int = 0
    overage_allowed: bool = False
    overage_minor_per_vcpu_hour: int = 0
    features: list[str] = field(default_factory=list)
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "PlanOffer":
        return cls(
            plan=str(raw.get("plan") or ""),
            name=str(raw.get("name") or ""),
            monthly_minor=_i(raw, "monthly_minor"),
            annual_monthly_minor=_i(raw, "annual_monthly_minor"),
            currency=str(raw.get("currency") or ""),
            per_seat=_b(raw, "per_seat"),
            included_vcpu_hours=_i(raw, "included_vcpu_hours"),
            max_concurrent_boxes=_i(raw, "max_concurrent_boxes"),
            max_vcpu_per_box=_i(raw, "max_vcpu_per_box"),
            network_egress=_b(raw, "network_egress"),
            max_lease_hours=_i(raw, "max_lease_hours"),
            object_storage_gb=_i(raw, "object_storage_gb"),
            overage_allowed=_b(raw, "overage_allowed"),
            overage_minor_per_vcpu_hour=_i(raw, "overage_minor_per_vcpu_hour"),
            features=_l(raw, "features"),
            raw=raw,
        )


@dataclass(kw_only=True)
class PlanState:
    plan: str = ""
    interval: Optional[str] = None
    paid_seats: int = 0
    overage_enabled: bool = False
    subscription_status: Optional[str] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool = False
    pending_plan: Optional[str] = None
    pending_interval: Optional[str] = None
    pending_effective_at: Optional[datetime] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "PlanState":
        return cls(
            plan=str(raw.get("plan") or ""),
            interval=_s(raw, "interval"),
            paid_seats=_i(raw, "paid_seats"),
            overage_enabled=_b(raw, "overage_enabled"),
            subscription_status=_s(raw, "subscription_status"),
            current_period_end=parse_time(raw.get("current_period_end")),
            cancel_at_period_end=_b(raw, "cancel_at_period_end"),
            pending_plan=_s(raw, "pending_plan"),
            pending_interval=_s(raw, "pending_interval"),
            pending_effective_at=parse_time(raw.get("pending_effective_at")),
            raw=raw,
        )


@dataclass(kw_only=True)
class CreditBalance:
    month: str = ""
    resets_at: Optional[datetime] = None
    included_vcpu_hours: str = ""
    used_vcpu_hours: str = ""
    remaining_vcpu_hours: str = ""
    overage_vcpu_hours: str = ""
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "CreditBalance":
        return cls(
            month=str(raw.get("month") or ""),
            resets_at=parse_time(raw.get("resets_at")),
            included_vcpu_hours=str(raw.get("included_vcpu_hours") or ""),
            used_vcpu_hours=str(raw.get("used_vcpu_hours") or ""),
            remaining_vcpu_hours=str(raw.get("remaining_vcpu_hours") or ""),
            overage_vcpu_hours=str(raw.get("overage_vcpu_hours") or ""),
            raw=raw,
        )


@dataclass(kw_only=True)
class Billing:
    """The billing page of a Sandscale organization: plan state, offer in force, balance and price book."""

    state: PlanState
    offer: PlanOffer
    balance: CreditBalance
    plans: list[PlanOffer] = field(default_factory=list)
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "Billing":
        return cls(
            state=PlanState.from_raw(_obj(raw, "state")),
            offer=PlanOffer.from_raw(_obj(raw, "offer")),
            balance=CreditBalance.from_raw(_obj(raw, "balance")),
            plans=[PlanOffer.from_raw(p) for p in raw.get("plans") or [] if isinstance(p, dict)],
            raw=raw,
        )


@dataclass(kw_only=True)
class Checkout:
    id: str
    #: Open this URL to pay.
    url: str = ""
    plan: str = ""
    interval: str = ""
    seats: int = 0
    expires_at: Optional[datetime] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "Checkout":
        return cls(
            id=str(raw.get("id") or ""),
            url=str(raw.get("url") or ""),
            plan=str(raw.get("plan") or ""),
            interval=str(raw.get("interval") or ""),
            seats=_i(raw, "seats"),
            expires_at=parse_time(raw.get("expires_at")),
            raw=raw,
        )


@dataclass(kw_only=True)
class Usage:
    month: str = ""
    vcpu_seconds_used: int = 0
    vcpu_seconds_left: int = 0
    running_boxes: int = 0
    running_by_region: dict[str, int] = field(default_factory=dict)
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "Usage":
        by = _obj(raw, "running_by_region")
        return cls(
            month=str(raw.get("month") or ""),
            vcpu_seconds_used=_i(raw, "vcpu_seconds_used"),
            vcpu_seconds_left=_i(raw, "vcpu_seconds_left"),
            running_boxes=_i(raw, "running_boxes"),
            running_by_region={str(k): int(v) for k, v in by.items() if isinstance(v, (int, float))},
            raw=raw,
        )


@dataclass(kw_only=True)
class RegionInfo:
    id: str
    status: str = ""
    api_url: Optional[str] = None
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "RegionInfo":
        return cls(id=str(raw.get("id")), status=str(raw.get("status") or ""), api_url=_s(raw, "api_url"), raw=raw)


@dataclass(kw_only=True)
class ApiKey:
    id: str
    name: str = ""
    key_prefix: str = ""
    scopes: list[str] = field(default_factory=list)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    #: ``active``, ``expired`` or ``revoked``.
    state: str = ""
    raw: Raw = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: Raw) -> "ApiKey":
        return cls(**_key_fields(raw))


def _key_fields(raw: Raw) -> dict[str, Any]:
    return {
        "id": str(raw.get("id")),
        "name": str(raw.get("name") or ""),
        "key_prefix": str(raw.get("key_prefix") or ""),
        "scopes": _l(raw, "scopes"),
        "expires_at": parse_time(raw.get("expires_at")),
        "last_used_at": parse_time(raw.get("last_used_at")),
        "revoked_at": parse_time(raw.get("revoked_at")),
        "created_at": parse_time(raw.get("created_at")),
        "state": str(raw.get("state") or ""),
        "raw": without(raw, "key"),
    }


@dataclass(kw_only=True)
class CreatedApiKey(ApiKey):
    """An API key as created or rotated. ``key`` is the secret, shown once: not in ``repr`` or ``raw``."""

    key: str = field(default="", repr=False, compare=False)
    rotated_from: Optional[str] = None
    previous_expires_at: Optional[datetime] = None

    @classmethod
    def from_raw(cls, raw: Raw) -> "CreatedApiKey":
        return cls(
            **_key_fields(raw),
            key=str(raw.get("key") or ""),
            rotated_from=_s(raw, "rotated_from"),
            previous_expires_at=parse_time(raw.get("previous_expires_at")),
        )


@dataclass
class ApiKeyLimits:
    max_days: Optional[int] = None
    max_active: Optional[int] = None


@dataclass(kw_only=True)
class ApiKeyList:
    api_keys: list[ApiKey] = field(default_factory=list)
    limits: ApiKeyLimits = field(default_factory=ApiKeyLimits)
