# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""What the API answers, as dataclasses. Every model keeps the server's full answer in ``raw``
and the ``region`` it was read from, so later calls on it go there."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, Mapping, Optional, TypeVar

from .errors import SandscaleError

T = TypeVar("T")
Raw = dict[str, Any]


def parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _str(raw: Mapping[str, Any], key: str) -> Optional[str]:
    value = raw.get(key)
    return value if isinstance(value, str) and value else None


@dataclass
class RegionPage:
    """One region's page of a list; lists without a region read every live region."""

    region: Optional[str]
    has_more: bool = False
    next_cursor: Optional[str] = None
    #: Set when this region could not be read; the other regions' items are still returned.
    error: Optional[SandscaleError] = None


@dataclass
class ListResult(Generic[T]):
    data: list[T] = field(default_factory=list)
    pages: list[RegionPage] = field(default_factory=list)


@dataclass
class Sandbox:
    id: str
    status: str
    raw: Raw
    region: Optional[str] = None
    name: Optional[str] = None
    template_id: Optional[str] = None
    cpu_count: Optional[int] = None
    memory_mb: Optional[int] = None
    timeout_seconds: Optional[int] = None
    status_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    can_pause: Optional[bool] = None
    can_resume: Optional[bool] = None

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Sandbox":
        suspend = raw.get("suspend") if isinstance(raw.get("suspend"), dict) else None
        return cls(
            id=str(raw.get("id")),
            status=str(raw.get("status") or ""),
            raw=raw,
            region=region,
            name=_str(raw, "name"),
            template_id=_str(raw, "template_id"),
            cpu_count=raw.get("cpu_count"),
            memory_mb=raw.get("mem_mb"),
            timeout_seconds=raw.get("ttl_seconds"),
            status_reason=_str(raw, "status_reason"),
            created_at=parse_time(raw.get("created_at")),
            can_pause=suspend.get("can_pause") if suspend else None,
            can_resume=suspend.get("can_resume") if suspend else None,
        )


@dataclass
class RunResult:
    run_id: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int = 0
    oom_killed: bool = False
    timed_out: bool = False
    #: True when the output callbacks received live output; False when they got it at the end.
    streamed: bool = False


@dataclass
class RunEnd:
    """How a run ended, as its log stream's done event says (``exit_code`` once it ended)."""

    run_id: str
    raw: Raw
    status: Optional[str] = None
    exit_code: Optional[int] = None
    oom_killed: bool = False
    timed_out: bool = False

    @classmethod
    def from_raw(cls, run_id: str, raw: Raw) -> "RunEnd":
        code = raw.get("exit_code")
        return cls(
            run_id=str(raw.get("run_id") or run_id),
            raw=raw,
            status=_str(raw, "status"),
            exit_code=code if isinstance(code, int) else None,
            oom_killed=raw.get("oom_killed") is True,
            timed_out=raw.get("timed_out") is True,
        )


@dataclass(frozen=True)
class VaultEnvRef:
    """One Keystone Vault value of a sandbox's environment: variable ``name`` gets ``field`` of
    the secret at ``path``."""

    name: str
    path: str
    field: str


@dataclass
class OutputChunk:
    stream: str  # "stdout" or "stderr"
    data: str
    chunk_index: int


@dataclass
class FileEntry:
    name: str
    path: str
    is_dir: bool
    size: Optional[int] = None


@dataclass
class Snapshot:
    id: str
    instance_id: str
    status: str
    label: str
    size_bytes: int
    raw: Raw
    region: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    failure: Optional[str] = None

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Snapshot":
        return cls(
            id=str(raw.get("id")),
            instance_id=str(raw.get("instance_id") or ""),
            status=str(raw.get("status") or ""),
            label=str(raw.get("label") or ""),
            size_bytes=int(raw.get("size_bytes") or 0),
            raw=raw,
            region=region,
            created_at=parse_time(raw.get("created_at")),
            expires_at=parse_time(raw.get("expires_at")),
            failure=_str(raw, "failure"),
        )


@dataclass
class Workspace:
    id: str
    name: str
    status: str
    raw: Raw
    region: Optional[str] = None
    health: Optional[str] = None
    template_id: Optional[str] = None
    owner_id: Optional[str] = None
    project_id: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Workspace":
        return cls(
            id=str(raw.get("id")),
            name=str(raw.get("name") or ""),
            status=str(raw.get("status") or ""),
            raw=raw,
            region=region,
            health=_str(raw, "health"),
            template_id=_str(raw, "template_id"),
            owner_id=_str(raw, "owner_id"),
            project_id=_str(raw, "project_id"),
            created_at=parse_time(raw.get("created_at")),
            last_used_at=parse_time(raw.get("last_used_at")),
        )


@dataclass
class WorkspaceBuild:
    """Start and stop are builds the server queues (202 Accepted)."""

    id: str
    workspace_id: str
    state: str
    raw: Raw
    region: Optional[str] = None
    desired_state: Optional[str] = None
    build_number: Optional[int] = None
    failure_message: Optional[str] = None

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "WorkspaceBuild":
        return cls(
            id=str(raw.get("id")),
            workspace_id=str(raw.get("workspace_id") or ""),
            state=str(raw.get("state") or ""),
            raw=raw,
            region=region,
            desired_state=_str(raw, "desired_state"),
            build_number=raw.get("build_number"),
            failure_message=_str(raw, "failure_message"),
        )


@dataclass
class ConnectInfo:
    ssh_host: str
    ssh_ready: bool
    raw: Raw
    ssh_command: Optional[str] = None
    port_forward_command: Optional[str] = None
    folder: Optional[str] = None
    ssh_unavailable_reason: Optional[str] = None
    links: list[Raw] = field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: Raw) -> "ConnectInfo":
        return cls(
            ssh_host=str(raw.get("ssh_host") or ""),
            ssh_ready=raw.get("ssh_ready") is True,
            raw=raw,
            ssh_command=_str(raw, "ssh_command"),
            port_forward_command=_str(raw, "port_forward_command"),
            folder=_str(raw, "folder"),
            ssh_unavailable_reason=_str(raw, "ssh_unavailable_reason"),
            links=list(raw.get("links") or []),
        )


@dataclass
class Lease:
    id: str
    pool_id: str
    state: str
    raw: Raw
    region: Optional[str] = None
    size: Optional[str] = None
    workspace_id: Optional[str] = None
    lab_host_id: Optional[str] = None
    ssh_user: Optional[str] = None
    expires_at: Optional[datetime] = None
    end_reason: Optional[str] = None

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Lease":
        size: Raw = raw["size"] if isinstance(raw.get("size"), dict) else {}
        host: Raw = raw["host"] if isinstance(raw.get("host"), dict) else {}
        return cls(
            id=str(raw.get("id")),
            pool_id=str(raw.get("pool_id") or ""),
            state=str(raw.get("state") or ""),
            raw=raw,
            region=region,
            size=_str(size, "name"),
            workspace_id=_str(raw, "workspace_id"),
            lab_host_id=_str(raw, "lab_host_id"),
            ssh_user=_str(host, "ssh_user"),
            expires_at=parse_time(raw.get("expires_at")),
            end_reason=_str(raw, "end_reason"),
        )


@dataclass
class Pool:
    id: str
    name: str
    backend: str
    raw: Raw
    region: Optional[str] = None
    sizes: list[str] = field(default_factory=list)
    requires_approval: bool = False

    @classmethod
    def from_raw(cls, raw: Raw, region: Optional[str]) -> "Pool":
        return cls(
            id=str(raw.get("id")),
            name=str(raw.get("name") or ""),
            backend=str(raw.get("backend") or ""),
            raw=raw,
            region=region,
            sizes=[str(s.get("name")) for s in raw.get("sizes") or [] if isinstance(s, dict)],
            requires_approval=raw.get("requires_approval") is True,
        )


@dataclass
class LeaseConnectInfo:
    lease: Lease
    #: "workspace": connect like a workspace; "lab": SSH through the relay; "pending": no host yet.
    kind: str
    workspace: Optional[ConnectInfo] = None
    #: For a lab lease: the relay path (WebSocket, binary SSH) on the region's API origin.
    ssh_relay_path: Optional[str] = None
    ssh_user: Optional[str] = None


@dataclass
class SSHCertificate:
    certificate: str
    serial: str
    key_id: str
    principals: list[str]
    ssh: Raw
    valid_after: Optional[datetime] = None
    valid_before: Optional[datetime] = None
