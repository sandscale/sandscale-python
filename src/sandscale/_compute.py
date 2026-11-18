# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Lab hosts and Agent Cloud tasks."""

from __future__ import annotations

from typing import Any, Optional

from ._services import list_across_regions
from ._transport import Transport, seg
from .admin_models import AgentTask, LabHost
from .models import ListResult, RegionPage

Raw = dict[str, Any]


class LabHosts:
    """Lab hosts of the organization (devices that serve build host leases)."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def _org(self) -> str:
        return seg(self._t.require_org())

    def list(self, *, region: Optional[str] = None) -> ListResult[LabHost]:
        def one(r: Optional[str]) -> tuple[list[LabHost], RegionPage]:
            raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/lab-hosts", region=r)
            return [LabHost.from_raw(h, r) for h in raw.get("lab_hosts") or []], RegionPage(region=r)

        return list_across_regions(self._t, region, one)

    def get(self, host_id: str, *, region: Optional[str] = None) -> LabHost:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/lab-hosts/{seg(host_id)}", region=region)
        return LabHost.from_raw(raw, self._t.region_of(region))

    def revoke(self, host_id: str, *, reason: Optional[str] = None, region: Optional[str] = None) -> LabHost:
        """Revokes the host (administrators): it takes no new leases and its certificate is withdrawn."""
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/build/lab-hosts/{seg(host_id)}/revoke",
            region=region,
            json_body={"reason": reason or ""},
        )
        return LabHost.from_raw(raw, self._t.region_of(region))


class AgentCloud:
    """Agent Cloud tasks: background coding-agent tasks, through Keystone's lead routes (never
    the device agent). These routes need a signed-in person's token; an API key is refused with
    403 ``person_required``. ``grant_id`` defaults to ``current``, the caller's one active lead grant."""

    def __init__(self, t: Transport) -> None:
        self._t = t

    def _org(self) -> str:
        return seg(self._t.require_org())

    def create_task(
        self,
        *,
        repository: str,
        brief: str,
        engine: str,
        ref: Optional[str] = None,
        mode: Optional[str] = None,
        access: Optional[str] = None,
        governance_mode: Optional[str] = None,
        target: Optional[str] = None,
        lease_id: Optional[str] = None,
        account_id: Optional[str] = None,
        pool_id: Optional[str] = None,
        cwd: Optional[str] = None,
        max_runtime_seconds: Optional[int] = None,
        grant_id: str = "current",
        region: Optional[str] = None,
    ) -> AgentTask:
        fields = {
            "repository": repository,
            "brief": brief,
            "engine": engine,
            "ref": ref,
            "mode": mode,
            "access": access,
            "governance_mode": governance_mode,
            "target": target,
            "lease_id": lease_id,
            "account_id": account_id,
            "pool_id": pool_id,
            "cwd": cwd,
            "max_runtime_seconds": max_runtime_seconds,
        }
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/build/leads/{seg(grant_id)}/tasks",
            region=region,
            json_body={k: v for k, v in fields.items() if v is not None},
        )
        return AgentTask.from_raw(raw, self._t.region_of(region))

    def list_tasks(
        self,
        *,
        state: Optional[str] = None,
        limit: Optional[int] = None,
        grant_id: str = "current",
        region: Optional[str] = None,
    ) -> ListResult[AgentTask]:
        def one(r: Optional[str]) -> tuple[list[AgentTask], RegionPage]:
            raw = self._t.request(
                "GET",
                f"/api/v1/orgs/{self._org()}/build/leads/{seg(grant_id)}/tasks",
                region=r,
                query={"state": state, "limit": limit},
            )
            return [AgentTask.from_raw(x, r) for x in raw.get("tasks") or []], RegionPage(region=r)

        return list_across_regions(self._t, region, one)

    def get_task(self, task_id: str, *, grant_id: str = "current", region: Optional[str] = None) -> AgentTask:
        raw = self._t.request(
            "GET", f"/api/v1/orgs/{self._org()}/build/leads/{seg(grant_id)}/tasks/{seg(task_id)}", region=region
        )
        return AgentTask.from_raw(raw, self._t.region_of(region))

    def cancel_task(self, task_id: str, *, grant_id: str = "current", region: Optional[str] = None) -> AgentTask:
        """Stops a queued task or a dispatched task's build task."""
        raw = self._t.request(
            "POST", f"/api/v1/orgs/{self._org()}/build/leads/{seg(grant_id)}/tasks/{seg(task_id)}/stop", region=region
        )
        return AgentTask.from_raw(raw, self._t.region_of(region))
