# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Sandscale Python SDK.

Every call goes to Sandscale's public API (https://api.sandscale.dev by default) as the API
key's or the signed-in person's own identity; the server decides what is allowed, the SDK only
carries the answer::

    from sandscale import Sandscale

    with Sandscale(region="eu") as sandscale:
        box = sandscale.sandboxes.create(template="builtin:python")
        run = sandscale.sandboxes.run(box.id, "python -V", region=box.region, on_stdout=print)
        sandscale.sandboxes.stop(box.id, region=box.region)
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

import httpx

from ._account import Account
from ._admin import Policy, Snapshots, Templates, Traces, Webhooks, verify_webhook_signature
from ._compute import AgentCloud, LabHosts
from ._objects import Objects
from ._services import BuildHosts, Sandboxes, Workspaces
from ._transport import DEFAULT_BASE_URL, SANDSCALE_REGION_URLS, TokenSource, Transport
from ._version import VERSION
from .errors import (
    APIConnectionError,
    AuthenticationError,
    ConfigurationError,
    ConflictError,
    EntitlementError,
    InvalidRequestError,
    KillSwitchError,
    LimitExceededError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    RegionError,
    SandscaleError,
    SandboxWakingError,
    ServerError,
    ServiceUnavailableError,
)
from .admin_models import (
    TraceCost,
    NoncurrentVersionExpiration,
    BucketUsage,
    BucketEndpoints,
    ApiKeyLimits,
    AppShareResult,
    AccessKey,
    AgentTask,
    ApiKey,
    ApiKeyList,
    BackupVerification,
    Billing,
    Bucket,
    BucketList,
    CacheEntry,
    CacheView,
    Checkout,
    CreatedAccessKey,
    CreatedApiKey,
    CreatedWebhook,
    CreditBalance,
    DefaultRetention,
    LabHost,
    LeaseArtifact,
    LeaseRun,
    LifecycleRule,
    ObjectsLimits,
    OpenLink,
    PlanOffer,
    PlanState,
    PortExposure,
    PreviewLink,
    RegionInfo,
    SandboxPolicy,
    SandboxSshCertificate,
    SandboxSshInfo,
    SnapshotList,
    SnapshotUsage,
    Template,
    TemplateBuildStatus,
    Trace,
    TraceBox,
    TraceCommand,
    TraceEvent,
    TraceExport,
    TraceExportTest,
    TraceFile,
    TraceSpan,
    TraceSummary,
    Usage,
    Webhook,
    WorkspaceApp,
    WorkspaceBackup,
)
from .models import (
    ConnectInfo,
    FileEntry,
    Lease,
    LeaseConnectInfo,
    ListResult,
    OutputChunk,
    Pool,
    RegionPage,
    RunEnd,
    RunResult,
    Sandbox,
    Snapshot,
    SSHCertificate,
    VaultEnvRef,
    Workspace,
    WorkspaceBuild,
)


class Sandscale:
    """The Sandscale client.

    :param api_key: a Sandscale API key (default ``$SANDSCALE_API_KEY``); give this or ``token``.
    :param token: the person's own sign-in access token, or a function returning a current one.
    :param base_url: default ``$SANDSCALE_BASE_URL``, else ``https://api.sandscale.dev``.
    :param org_id: sent as ``X-Org-ID`` and used by the workspace and build host routes
        (default ``$SANDSCALE_ORG_ID``).
    :param region: region of every call that names none (``"us"`` or ``"eu"``).
    :param region_urls: explicit API URL per region instead of the server's region list.
    :param timeout: per-request timeout in seconds.
    :param max_retries: retries of safe (GET) calls after a connection error, 429, 502, 503, 504.
    """

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
        self.transport = Transport(
            api_key=api_key,
            token=token,
            base_url=base_url,
            org_id=org_id,
            region=region,
            region_urls=region_urls,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
        )
        self.sandboxes = Sandboxes(self.transport)
        self.workspaces = Workspaces(self.transport)
        self.build_hosts = BuildHosts(self.transport, self.workspaces)
        self.snapshots = Snapshots(self.transport)
        self.templates = Templates(self.transport)
        self.policy = Policy(self.transport)
        self.webhooks = Webhooks(self.transport)
        self.traces = Traces(self.transport)
        self.objects = Objects(self.transport)
        self.lab_hosts = LabHosts(self.transport)
        self.agent_cloud = AgentCloud(self.transport)
        self.account = Account(self.transport)

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "Sandscale":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


__all__ = [
    "Sandscale",
    "Sandboxes",
    "Workspaces",
    "BuildHosts",
    "Transport",
    "DEFAULT_BASE_URL",
    "SANDSCALE_REGION_URLS",
    "VERSION",
    "SandscaleError",
    "ConfigurationError",
    "APIConnectionError",
    "AuthenticationError",
    "ConflictError",
    "EntitlementError",
    "InvalidRequestError",
    "KillSwitchError",
    "LimitExceededError",
    "NotFoundError",
    "PermissionDeniedError",
    "RateLimitError",
    "RegionError",
    "ServerError",
    "ConnectInfo",
    "FileEntry",
    "Lease",
    "LeaseConnectInfo",
    "ListResult",
    "OutputChunk",
    "Pool",
    "RegionPage",
    "RunEnd",
    "RunResult",
    "Sandbox",
    "Snapshot",
    "SSHCertificate",
    "VaultEnvRef",
    "Workspace",
    "WorkspaceBuild",
    "Account",
    "TraceCost",
    "NoncurrentVersionExpiration",
    "BucketUsage",
    "BucketEndpoints",
    "ApiKeyLimits",
    "AppShareResult",
    "Policy",
    "Snapshots",
    "Templates",
    "Traces",
    "Webhooks",
    "Objects",
    "LabHosts",
    "AgentCloud",
    "verify_webhook_signature",
    "SandboxWakingError",
    "ServiceUnavailableError",
    "AccessKey",
    "AgentTask",
    "ApiKey",
    "ApiKeyList",
    "BackupVerification",
    "Billing",
    "Bucket",
    "BucketList",
    "CacheEntry",
    "CacheView",
    "Checkout",
    "CreatedAccessKey",
    "CreatedApiKey",
    "CreatedWebhook",
    "CreditBalance",
    "DefaultRetention",
    "LabHost",
    "LeaseArtifact",
    "LeaseRun",
    "LifecycleRule",
    "ObjectsLimits",
    "OpenLink",
    "PlanOffer",
    "PlanState",
    "PortExposure",
    "PreviewLink",
    "RegionInfo",
    "SandboxPolicy",
    "SandboxSshCertificate",
    "SandboxSshInfo",
    "SnapshotList",
    "SnapshotUsage",
    "Template",
    "TemplateBuildStatus",
    "Trace",
    "TraceBox",
    "TraceCommand",
    "TraceEvent",
    "TraceExport",
    "TraceExportTest",
    "TraceFile",
    "TraceSpan",
    "TraceSummary",
    "Usage",
    "Webhook",
    "WorkspaceApp",
    "WorkspaceBackup",
]
