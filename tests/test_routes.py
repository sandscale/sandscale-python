# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""The routes this SDK calls. The test fails when the SDK calls a route not listed here and, when
SANDSCALE_ROUTE_INVENTORY names the server's route inventory files (colon separated; the source
repository sets it), when the server stops mounting one of them."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

import pytest

from sandscale import Sandscale

from .mock_server import MockServer, Recorded, Reply

ROUTES = [
    "GET /api/v1/regions",
    "POST /api/v1/sandbox/instances",
    "GET /api/v1/sandbox/instances",
    "GET /api/v1/sandbox/instances/{}",
    "DELETE /api/v1/sandbox/instances/{}",
    "POST /api/v1/sandbox/instances/{}/pause",
    "POST /api/v1/sandbox/instances/{}/resume",
    "POST /api/v1/sandbox/instances/{}/keep-awake",
    "POST /api/v1/sandbox/instances/{}/prepare",
    "POST /api/v1/sandbox/instances/{}/snapshot",
    "GET /api/v1/sandbox/instances/{}/snapshots",
    "POST /api/v1/sandbox/instances/{}/exec",
    "GET /api/v1/sandbox/runs/{}",
    "GET /api/v1/sandbox/instances/{}/logs",
    "PUT /api/v1/sandbox/instances/{}/files",
    "GET /api/v1/sandbox/instances/{}/files",
    "GET /api/v1/orgs/{}/workspaces",
    "GET /api/v1/orgs/{}/workspaces/{}",
    "POST /api/v1/orgs/{}/workspaces/{}/start",
    "POST /api/v1/orgs/{}/workspaces/{}/stop",
    "GET /api/v1/orgs/{}/workspaces/{}/connect",
    "GET /api/v1/orgs/{}/build/pools",
    "POST /api/v1/orgs/{}/build/pools/{}/leases",
    "GET /api/v1/orgs/{}/build/leases",
    "GET /api/v1/orgs/{}/build/leases/{}",
    "POST /api/v1/orgs/{}/build/leases/{}/release",
    "POST /api/v1/orgs/{}/build/leases/{}/ssh/certificate",
    "POST /api/v1/sandbox/instances/{}/ports",
    "GET /api/v1/sandbox/instances/{}/ports",
    "DELETE /api/v1/sandbox/instances/{}/ports/{}",
    "POST /api/v1/sandbox/instances/{}/ports/{}/preview-links",
    "GET /api/v1/sandbox/instances/{}/preview-links",
    "DELETE /api/v1/sandbox/instances/{}/preview-links/{}",
    "GET /api/v1/sandbox/instances/{}/ssh",
    "POST /api/v1/sandbox/instances/{}/ssh/certificate",
    "GET /api/v1/sandbox/snapshots",
    "GET /api/v1/sandbox/snapshots/{}",
    "DELETE /api/v1/sandbox/snapshots/{}",
    "POST /api/v1/sandbox/templates",
    "GET /api/v1/sandbox/templates",
    "GET /api/v1/sandbox/templates/{}",
    "DELETE /api/v1/sandbox/templates/{}",
    "GET /api/v1/sandbox/templates/{}/build-status",
    "GET /api/v1/sandbox/policy",
    "PUT /api/v1/sandbox/policy",
    "GET /api/v1/sandbox/webhooks",
    "POST /api/v1/sandbox/webhooks",
    "DELETE /api/v1/sandbox/webhooks/{}",
    "GET /api/v1/sandbox/traces",
    "GET /api/v1/sandbox/traces/{}",
    "GET /api/v1/sandbox/trace-export",
    "PUT /api/v1/sandbox/trace-export",
    "DELETE /api/v1/sandbox/trace-export",
    "POST /api/v1/sandbox/trace-export/test",
    "POST /api/v1/svc/objects/CreateBucket",
    "POST /api/v1/svc/objects/ListBuckets",
    "POST /api/v1/svc/objects/DescribeBucket",
    "POST /api/v1/svc/objects/UpdateBucket",
    "POST /api/v1/svc/objects/DeleteBucket",
    "POST /api/v1/svc/objects/PutBucketLifecycle",
    "POST /api/v1/svc/objects/GetBucketLifecycle",
    "POST /api/v1/svc/objects/DeleteBucketLifecycle",
    "POST /api/v1/svc/objects/PutBucketPolicy",
    "POST /api/v1/svc/objects/GetBucketPolicy",
    "POST /api/v1/svc/objects/DeleteBucketPolicy",
    "POST /api/v1/svc/objects/CreateAccessKey",
    "POST /api/v1/svc/objects/ListAccessKeys",
    "POST /api/v1/svc/objects/UpdateAccessKey",
    "POST /api/v1/svc/objects/DeleteAccessKey",
    "POST /api/v1/svc/objects/DescribeObjectsLimits",
    "POST /api/v1/orgs/{}/workspaces",
    "PATCH /api/v1/orgs/{}/workspaces/{}",
    "DELETE /api/v1/orgs/{}/workspaces/{}",
    "POST /api/v1/orgs/{}/workspaces/{}/rebuild",
    "GET /api/v1/orgs/{}/workspaces/{}/open",
    "GET /api/v1/orgs/{}/workspaces/{}/backups",
    "POST /api/v1/orgs/{}/workspaces/{}/backups",
    "POST /api/v1/orgs/{}/backups/{}/verify",
    "GET /api/v1/orgs/{}/workspaces/{}/apps",
    "PATCH /api/v1/orgs/{}/workspaces/{}/apps/{}/share",
    "POST /api/v1/orgs/{}/build/leases/{}/renew",
    "POST /api/v1/orgs/{}/build/leases/{}/kill",
    "GET /api/v1/orgs/{}/build/leases/{}/runs",
    "GET /api/v1/orgs/{}/build/leases/{}/runs/{}",
    "GET /api/v1/orgs/{}/build/leases/{}/artifacts",
    "GET /api/v1/orgs/{}/build/leases/{}/artifacts/{}",
    "GET /api/v1/orgs/{}/build/leases/{}/artifacts/{}/content",
    "DELETE /api/v1/orgs/{}/build/leases/{}/artifacts/{}",
    "GET /api/v1/orgs/{}/build/leases/{}/caches",
    "GET /api/v1/orgs/{}/build/pools/{}/caches",
    "DELETE /api/v1/orgs/{}/build/pools/{}/caches/{}",
    "GET /api/v1/orgs/{}/build/lab-hosts",
    "GET /api/v1/orgs/{}/build/lab-hosts/{}",
    "POST /api/v1/orgs/{}/build/lab-hosts/{}/revoke",
    "POST /api/v1/orgs/{}/build/leads/{}/tasks",
    "GET /api/v1/orgs/{}/build/leads/{}/tasks",
    "GET /api/v1/orgs/{}/build/leads/{}/tasks/{}",
    "POST /api/v1/orgs/{}/build/leads/{}/tasks/{}/stop",
    "GET /api/v1/orgs/{}/sandscale/billing",
    "POST /api/v1/orgs/{}/sandscale/billing/plan",
    "PUT /api/v1/orgs/{}/sandscale/billing/overage",
    "DELETE /api/v1/orgs/{}/sandscale/billing/plan/pending",
    "POST /api/v1/orgs/{}/sandscale/billing/checkout",
    "GET /api/v1/sandscale/usage",
    "GET /api/v1/account/api-keys",
    "POST /api/v1/account/api-keys",
    "POST /api/v1/account/api-keys/{}/rotate",
    "DELETE /api/v1/account/api-keys/{}",
]

#: The server's route inventory files, colon separated. The source repository sets
#: SANDSCALE_ROUTE_INVENTORY; without it the contract check is skipped.
INVENTORY_FILES = [Path(p) for p in os.environ.get("SANDSCALE_ROUTE_INVENTORY", "").split(":") if p]


@pytest.mark.skipif(not INVENTORY_FILES or not all(p.exists() for p in INVENTORY_FILES), reason="SANDSCALE_ROUTE_INVENTORY is not set")
def test_server_mounts_every_route() -> None:
    mounted: set[str] = set()
    for inventory in INVENTORY_FILES:
        for line in inventory.read_text().splitlines():
            m = re.match(r"^(?:\S+ )?((?:GET|POST|PUT|PATCH|DELETE) /\S*)", line)
            if m:
                mounted.add(re.sub(r"\{[^}/]*\}", "{}", m.group(1)))
    missing = [r for r in ROUTES if r not in mounted]
    assert missing == [], f"routes the SDK calls that the server no longer mounts: {missing}"


@pytest.fixture()
def api() -> Iterator[MockServer]:
    server = MockServer()
    lease = {"id": "l", "pool_id": "p", "state": "active", "workspace_id": "w"}
    for route in ROUTES:
        method, pattern = route.split(" ")

        def handler(_req: Recorded, reply: Reply, route: str = route, method: str = method) -> None:
            if route == "GET /api/v1/regions":
                reply.json(200, {"regions": [{"id": "us1", "status": "live", "api_url": server.url}]})
            elif route.endswith("/logs"):
                reply.sse([("done", {})])
            elif route.endswith("/exec"):
                reply.json(202, {"run_id": "r", "status": "queued"})
            elif route == "GET /api/v1/sandbox/runs/{}":
                reply.json(200, {"id": "r", "status": "succeeded", "exit_code": 0})
            elif route.endswith("/snapshots"):
                reply.json(200, {"snapshots": []})
            elif route.endswith("/instances") and method == "GET":
                reply.json(200, {"data": []})
            elif route.endswith("/files") and method == "GET":
                reply.json(200, {"type": "file", "content": ""})
            elif route.endswith("/pools"):
                reply.json(200, {"pools": []})
            elif route.endswith("/leases") and method == "GET":
                reply.json(200, {"leases": []})
            elif "/build/" in route:
                reply.json(200, lease)
            elif method == "DELETE":
                reply.json(204)
            elif "/svc/objects/" in route:
                reply.json(200, {})
            elif route.endswith("/content"):
                reply.json(200, {})
            elif route.endswith("/preview-links") and method == "GET":
                reply.json(200, {"preview_links": []})
            elif route.endswith("/ports") and method == "GET":
                reply.json(200, {"ports": []})
            elif route.endswith("/webhooks") and method == "GET":
                reply.json(200, {"webhooks": []})
            elif route.endswith("/templates") and method == "GET":
                reply.json(200, {"data": []})
            elif route.endswith("/snapshots") and False:
                reply.json(200, {})
            else:
                reply.json(200, {"id": "x", "status": "running"})

        server.on(method, pattern, handler)
    yield server
    server.stop()


def test_sdk_calls_exactly_the_listed_routes(api: MockServer) -> None:
    c = Sandscale(api_key="k", base_url=api.url, org_id="o")
    s = c.sandboxes
    s.create(region="us")
    s.list()
    s.get("x")
    s.stop("x")
    s.pause("x")
    s.resume("x")
    s.keep_awake("x", 60, reason="dev server")
    s.prepare("x")
    s.snapshot("x")
    s.list_snapshots("x")
    s.run("x", ["true"])
    s.run("x", ["true"], on_stdout=lambda _d: None)
    list(s.logs("x", "r"))
    s.write_file("x", "/workspace/a", "a")
    s.read_file("x", "/workspace/a")
    w = c.workspaces
    w.list()
    w.get("w")
    w.start("w")
    w.stop("w")
    w.connect_info("w")
    b = c.build_hosts
    b.list_pools()
    b.list()
    b.start("p")
    b.get("l")
    b.stop("l")
    b.connect_info("l")
    b.ssh_certificate("l", "ssh-ed25519 AAAA")
    s.expose_port("x", 8080)
    s.list_ports("x")
    s.close_port("x", 8080)
    s.create_preview_link("x", 8080, visibility="team")
    s.list_preview_links("x")
    s.revoke_preview_link("x", "k")
    s.ssh_info("x")
    s.ssh_certificate("x", "ssh-ed25519 AAAA")
    c.snapshots.list()
    c.snapshots.get("s")
    c.snapshots.delete("s")
    c.templates.create(name="tt", image="r/x@sha256:1")
    c.templates.list()
    c.templates.get("t")
    c.templates.delete("t")
    c.templates.build_status("t")
    c.policy.get()
    c.policy.set(max_cpu=1)
    c.webhooks.list()
    c.webhooks.create(url="https://h.test/x")
    c.webhooks.delete("w")
    c.traces.list()
    c.traces.get("a" * 32)
    c.traces.get_export()
    c.traces.set_export(protocol="otlp_http", endpoint="https://o.test")
    c.traces.delete_export()
    c.traces.test_export()
    o = c.objects
    o.create_bucket("b")
    o.list_buckets()
    o.get_bucket("b")
    o.update_bucket("b", presign=True)
    o.delete_bucket("b")
    o.put_lifecycle("b", [])
    o.get_lifecycle("b")
    o.delete_lifecycle("b")
    o.put_policy("b", "{}")
    o.get_policy("b")
    o.delete_policy("b")
    o.create_access_key()
    o.list_access_keys()
    o.update_access_key("k", "Inactive")
    o.delete_access_key("k")
    o.limits()
    w.create(name="n", template_id="t")
    w.update("w", name="m")
    w.delete("w")
    w.rebuild("w")
    w.open_link("w", "vscode")
    w.list_backups("w")
    w.create_backup("w")
    w.verify_backup("bk")
    w.list_apps("w")
    w.share_app("w", "web", "org")
    b.renew("l", 60)
    b.kill("l")
    b.list_runs("l")
    b.get_run("l", "r")
    b.list_artifacts("l")
    b.get_artifact("l", "a")
    b.download_artifact("l", "a")
    b.delete_artifact("l", "a")
    b.list_caches("l")
    b.list_pool_caches("p")
    b.purge_pool_cache("p", "npm")
    c.lab_hosts.list()
    c.lab_hosts.get("h")
    c.lab_hosts.revoke("h")
    c.agent_cloud.create_task(repository="r", brief="b", engine="codex")
    c.agent_cloud.list_tasks()
    c.agent_cloud.get_task("t")
    c.agent_cloud.cancel_task("t")
    a = c.account
    a.billing()
    a.change_plan(plan="pro")
    a.set_overage(True)
    a.cancel_pending_plan_change()
    a.checkout(plan="pro", interval="month")
    a.usage()
    a.regions()
    a.list_api_keys()
    a.create_api_key(name="n", expires_at="2027-01-01T00:00:00Z")
    a.rotate_api_key("k")
    a.delete_api_key("k")
    called = {re.sub(r"/orgs/[^/]+", "/orgs/{}", r.route) for r in api.requests}
    assert sorted(called) == sorted(ROUTES)
