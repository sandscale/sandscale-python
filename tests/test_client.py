# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import threading
import time
from typing import Any, Iterator

import httpx
import pytest

from sandscale import (
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
    Sandscale,
    SandscaleError,
    ServerError,
    VaultEnvRef,
)

from .mock_server import MockServer, Recorded, Reply, error_body

ORG = "org-1"
SANDBOX = {"id": "sb-1", "status": "running", "created_at": "2026-11-17T00:00:00Z", "mem_mb": 512, "cpu_count": 1}


@pytest.fixture()
def api() -> Iterator[MockServer]:
    server = MockServer()
    yield server
    server.stop()


@pytest.fixture()
def sleeps() -> list[float]:
    return []


def make(api: MockServer, sleeps: list[float], **kw: Any) -> Sandscale:
    c = Sandscale(**{"api_key": "ssk_test", "base_url": api.url, "org_id": ORG, **kw})
    c.transport.sleep = sleeps.append
    return c


# --- configuration ------------------------------------------------------------------------


def test_requires_one_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SANDSCALE_API_KEY", raising=False)
    with pytest.raises(ConfigurationError):
        Sandscale(base_url="https://x.test")
    with pytest.raises(ConfigurationError):
        Sandscale(api_key="a", token="b", base_url="https://x.test")


def test_refuses_unsafe_urls() -> None:
    with pytest.raises(ConfigurationError, match="https"):
        Sandscale(api_key="k", base_url="http://api.example.com")
    with pytest.raises(ConfigurationError, match="credentials"):
        Sandscale(api_key="k", base_url="https://u:p@api.example.com")
    assert Sandscale(api_key="k").transport.base_url == "https://api.sandscale.dev"


def test_org_required_for_org_routes(api: MockServer) -> None:
    with pytest.raises(ConfigurationError):
        Sandscale(api_key="k", base_url=api.url).workspaces.get("w")


def test_sends_key_org_and_user_agent(api: MockServer, sleeps: list[float]) -> None:
    api.json("GET", "/api/v1/sandbox/instances/{}", 200, SANDBOX)
    make(api, sleeps).sandboxes.get("sb-1")
    h = api.requests[0].headers
    assert h["authorization"] == "Bearer ssk_test"
    assert h["x-org-id"] == ORG
    assert h["user-agent"].startswith("sandscale-sdk-python/")


def test_token_function_called_per_request(api: MockServer) -> None:
    n = iter(range(1, 10))
    api.json("GET", "/api/v1/sandbox/instances/{}", 200, SANDBOX)
    c = Sandscale(token=lambda: f"tok-{next(n)}", base_url=api.url)
    c.sandboxes.get("a")
    c.sandboxes.get("a")
    assert [r.headers["authorization"] for r in api.requests] == ["Bearer tok-1", "Bearer tok-2"]


# --- errors -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status,code,cls",
    [
        (400, "invalid_request", InvalidRequestError),
        (401, "invalid_token", AuthenticationError),
        (403, "host_access_denied", PermissionDeniedError),
        (404, "instance_not_found", NotFoundError),
        (409, "pause_unsupported", ConflictError),
        (402, "quota_exceeded", LimitExceededError),
        (409, "snapshot_quota_exceeded", LimitExceededError),
        (403, "not_entitled", EntitlementError),
        (402, "payment_required", EntitlementError),
        (503, "kill_switch_engaged", KillSwitchError),
        (401, "wrong_region", RegionError),
        (500, "internal_error", ServerError),
    ],
)
def test_errors_carry_server_code(api: MockServer, sleeps: list[float], status: int, code: str, cls: type) -> None:
    api.json("POST", "/api/v1/sandbox/instances", status, error_body(code, f"server says {code}", detail={"limit": 2}))
    with pytest.raises(cls) as info:
        make(api, sleeps).sandboxes.create(template="builtin:base")
    err = info.value
    assert isinstance(err, SandscaleError)
    assert (err.status, err.code, err.message, err.request_id, err.details) == (
        status,
        code,
        f"server says {code}",
        "req-1",
        {"limit": 2},
    )


def test_wrong_region_answer(api: MockServer, sleeps: list[float]) -> None:
    body = {"code": "wrong_region", "region": "eu1", "error": {"code": "wrong_region", "message": "m", "region": "eu1"}}
    api.json("GET", "/api/v1/sandbox/instances/{}", 401, body)
    with pytest.raises(RegionError) as info:
        make(api, sleeps).sandboxes.get("x")
    assert info.value.region == "eu1"


def test_rate_limit_retry_after(api: MockServer, sleeps: list[float]) -> None:
    api.json("POST", "/api/v1/sandbox/instances", 429, error_body("rate_limited", "slow"), {"Retry-After": "7"})
    with pytest.raises(RateLimitError) as info:
        make(api, sleeps).sandboxes.create()
    assert isinstance(info.value, LimitExceededError)
    assert info.value.retry_after == 7.0


# --- retries ------------------------------------------------------------------------------


def test_retries_safe_call(api: MockServer, sleeps: list[float]) -> None:
    answers = iter(
        [
            (503, error_body("provisioner_unavailable", "busy"), None),
            (429, error_body("rate_limited", "slow"), {"Retry-After": "2"}),
            (200, SANDBOX, None),
        ]
    )

    def handler(_req: Recorded, reply: Reply) -> None:
        status, body, headers = next(answers)
        reply.json(status, body, headers)

    api.on("GET", "/api/v1/sandbox/instances/{}", handler)
    assert make(api, sleeps).sandboxes.get("sb-1").id == "sb-1"
    assert len(api.requests) == 3
    assert sleeps[1] == 2.0


def test_never_retries_unsafe_call_or_kill_switch(api: MockServer, sleeps: list[float]) -> None:
    api.json("POST", "/api/v1/sandbox/instances", 503, error_body("provisioner_unavailable", "busy"))
    api.json("GET", "/api/v1/sandbox/instances/{}", 503, error_body("kill_switch_engaged", "stopped"))
    c = make(api, sleeps)
    with pytest.raises(ServerError):
        c.sandboxes.create()
    with pytest.raises(KillSwitchError):
        c.sandboxes.get("x")
    assert len(api.requests) == 2


def test_gives_up_after_max_retries(api: MockServer, sleeps: list[float]) -> None:
    api.json("GET", "/api/v1/sandbox/instances/{}", 502, error_body("bad_gateway", "down"))
    with pytest.raises(ServerError):
        make(api, sleeps, max_retries=1).sandboxes.get("x")
    assert len(api.requests) == 2


def test_connection_error(api: MockServer) -> None:
    url = api.url
    api.stop()
    with pytest.raises(APIConnectionError):
        Sandscale(api_key="k", base_url=url, max_retries=0).sandboxes.get("x")


# --- regions ------------------------------------------------------------------------------


@pytest.fixture()
def eu(api: MockServer) -> Iterator[MockServer]:
    server = MockServer()
    api.json(
        "GET",
        "/api/v1/regions",
        200,
        {
            "current": "us1",
            "regions": [
                {"id": "us1", "status": "live", "api_url": api.url},
                {"id": "eu1", "status": "live", "api_url": server.url},
                {"id": "jp1", "status": "coming_soon", "api_url": ""},
            ],
        },
    )
    yield server
    server.stop()


def test_region_routing(api: MockServer, eu: MockServer, sleeps: list[float]) -> None:
    eu.json("POST", "/api/v1/sandbox/instances", 201, {"id": "sb-eu", "status": "starting"})
    sb = make(api, sleeps).sandboxes.create(template="builtin:base", region="eu")
    assert (sb.id, sb.region) == ("sb-eu", "eu")
    assert eu.requests[0].headers["authorization"] == "Bearer ssk_test"
    assert api.requests[0].path == "/api/v1/regions"
    assert "authorization" not in api.requests[0].headers


def test_client_region_and_refusals(api: MockServer, eu: MockServer, sleeps: list[float]) -> None:
    eu.json("GET", "/api/v1/sandbox/instances/{}", 200, SANDBOX)
    make(api, sleeps, region="eu1").sandboxes.get("sb-1")
    assert len(eu.requests) == 1
    with pytest.raises(RegionError, match="no region"):
        make(api, sleeps).sandboxes.get("x", region="ap")
    with pytest.raises(RegionError) as info:
        make(api, sleeps).sandboxes.get("x", region="jp")
    assert info.value.code == "region_unavailable"


def test_list_reads_every_live_region(api: MockServer, eu: MockServer, sleeps: list[float]) -> None:
    api.json("GET", "/api/v1/sandbox/instances", 200, {"data": [{"id": "a", "status": "running"}], "next_cursor": "c1", "has_more": True})
    eu.json("GET", "/api/v1/sandbox/instances", 503, error_body("provisioner_unavailable", "down"))
    result = make(api, sleeps, max_retries=0).sandboxes.list()
    assert [(s.id, s.region) for s in result.data] == [("a", "us1")]
    assert (result.pages[0].region, result.pages[0].next_cursor, result.pages[0].has_more) == ("us1", "c1", True)
    assert isinstance(result.pages[1].error, ServerError)


def test_explicit_region_urls(api: MockServer, sleeps: list[float]) -> None:
    other = MockServer()
    try:
        other.json("GET", "/api/v1/sandbox/instances/{}", 200, SANDBOX)
        make(api, sleeps, region_urls={"eu": other.url}).sandboxes.get("sb-1", region="eu")
        assert api.requests == [] and len(other.requests) == 1
    finally:
        other.stop()


# --- sandboxes ----------------------------------------------------------------------------


def test_create_maps_fields(api: MockServer, sleeps: list[float]) -> None:
    api.json("POST", "/api/v1/sandbox/instances", 201, SANDBOX)
    sb = make(api, sleeps).sandboxes.create(
        template="builtin:python",
        cpu_count=2,
        memory_mb=1024,
        disk_mb=2048,
        timeout_seconds=600,
        env={"A": "1"},
        vault_env=[VaultEnvRef("DB_PASSWORD", "secret/data/db", "password")],
        name="n",
        labels={"team": "x"},
    )
    assert api.requests[0].json() == {
        "template_id": "builtin:python",
        "cpu_count": 2,
        "mem_mb": 1024,
        "disk_mb": 2048,
        "ttl_seconds": 600,
        "env": {"A": "1"},
        "vault_env": [{"name": "DB_PASSWORD", "path": "secret/data/db", "field": "password"}],
        "name": "n",
        "labels": {"team": "x"},
    }
    assert (sb.id, sb.status, sb.memory_mb) == ("sb-1", "running", 512)
    assert sb.created_at is not None and sb.created_at.year == 2026


def test_list_filters(api: MockServer, sleeps: list[float]) -> None:
    api.json("GET", "/api/v1/sandbox/instances", 200, {"data": [SANDBOX], "next_cursor": None, "has_more": False})
    result = make(api, sleeps, region_urls={"us": api.url}).sandboxes.list(status="running", limit=10, cursor="c", region="us")
    assert api.requests[0].query == {"status": "running", "limit": "10", "cursor": "c"}
    assert len(result.data) == 1 and result.pages[0].region == "us"


def test_stop_pause_resume_snapshot(api: MockServer, sleeps: list[float]) -> None:
    snap = {"id": "sn-1", "instance_id": "sb-1", "status": "creating", "label": "l", "size_bytes": 0}
    api.on("DELETE", "/api/v1/sandbox/instances/{}", lambda _r, reply: reply.json(204))
    api.json("POST", "/api/v1/sandbox/instances/{}/pause", 200, {"id": "sb-1", "status": "paused"})
    api.json("POST", "/api/v1/sandbox/instances/{}/resume", 200, {"id": "sb-1", "status": "running"})
    api.json("POST", "/api/v1/sandbox/instances/{}/snapshot", 201, snap)
    api.json("GET", "/api/v1/sandbox/instances/{}/snapshots", 200, {"snapshots": [snap]})
    c = make(api, sleeps)
    c.sandboxes.stop("sb-1")
    assert c.sandboxes.pause("sb-1") == {"id": "sb-1", "status": "paused"}
    assert c.sandboxes.resume("sb-1")["status"] == "running"
    assert c.sandboxes.snapshot("sb-1", label="l").status == "creating"
    assert api.requests[3].json() == {"label": "l"}
    assert [s.id for s in c.sandboxes.list_snapshots("sb-1")] == ["sn-1"]


def test_files(api: MockServer, sleeps: list[float]) -> None:
    api.json("PUT", "/api/v1/sandbox/instances/{}/files", 200, {})

    def files(req: Recorded, reply: Reply) -> None:
        if req.query["path"] == "/workspace":
            reply.json(200, {"type": "dir", "entries": [{"name": "a.txt", "type": "file", "size_bytes": 2}, {"name": "d", "type": "dir"}]})
        else:
            reply.json(200, {"type": "file", "content": base64.b64encode(b"hi").decode()})

    api.on("GET", "/api/v1/sandbox/instances/{}/files", files)
    c = make(api, sleeps)
    c.sandboxes.write_file("sb-1", "/workspace/a.txt", "hi", mode="0644")
    assert api.requests[0].json() == {"path": "/workspace/a.txt", "content": "aGk=", "mode": "0644"}
    assert c.sandboxes.read_file("sb-1", "/workspace/a.txt") == b"hi"
    entries = c.sandboxes.list_files("sb-1", "/workspace")
    assert [(e.path, e.is_dir, e.size) for e in entries] == [("/workspace/a.txt", False, 2), ("/workspace/d", True, None)]


def test_run_returns_exit_code_and_output(api: MockServer, sleeps: list[float]) -> None:
    api.json("POST", "/api/v1/sandbox/instances/{}/exec", 200, {"run_id": "r1", "exit_code": 3, "stdout": "o", "stderr": "e", "duration_ms": 5})
    res = make(api, sleeps).sandboxes.run("sb-1", "exit 3", env={"X": "1"}, workdir="/workspace/p", timeout=5, stdin="in")
    assert api.requests[0].json() == {
        "command": ["sh", "-c", "exit 3"],
        "timeout_sec": 5,
        "env": {"X": "1"},
        "workdir": "/workspace/p",
        "stdin": "aW4=",
    }
    assert (res.run_id, res.exit_code, res.stdout, res.stderr, res.duration_ms, res.streamed) == ("r1", 3, "o", "e", 5, False)


def test_run_streams_by_run_id(api: MockServer, sleeps: list[float]) -> None:
    def exec_(req: Recorded, reply: Reply) -> None:
        assert req.json()["wait"] is False
        reply.json(202, {"run_id": "r2", "status": "queued"})

    def logs(req: Recorded, reply: Reply) -> None:
        assert req.query["run_id"] == "r2"
        reply.sse(
            [
                ("chunk", {"chunk_index": 0, "stream": "stdout", "data": "hi\n"}),
                ("chunk", {"chunk_index": 1, "stream": "stderr", "data": "w\n"}),
                ("done", {"run_id": "r2", "status": "failed", "exit_code": 4, "oom_killed": False, "timed_out": False}),
            ]
        )

    api.on("POST", "/api/v1/sandbox/instances/{}/exec", exec_)
    api.on("GET", "/api/v1/sandbox/instances/{}/logs", logs)
    out: list[str] = []
    res = make(api, sleeps).sandboxes.run(
        "sb-1", ["echo", "hi"], on_stdout=lambda d: out.append("out:" + d), on_stderr=lambda d: out.append("err:" + d)
    )
    assert out == ["out:hi\n", "err:w\n"]
    assert (res.run_id, res.exit_code, res.stdout, res.stderr, res.streamed) == ("r2", 4, "hi\n", "w\n", True)
    # No run listing: the run is known by its id.
    assert [r.route for r in api.requests] == ["POST /api/v1/sandbox/instances/{}/exec", "GET /api/v1/sandbox/instances/{}/logs"]


def test_run_reads_the_run_without_a_result_in_done(api: MockServer, sleeps: list[float]) -> None:
    api.json("POST", "/api/v1/sandbox/instances/{}/exec", 202, {"run_id": "r3", "status": "queued"})
    api.on("GET", "/api/v1/sandbox/instances/{}/logs", lambda _r, reply: reply.sse([("done", {})]))
    api.json("GET", "/api/v1/sandbox/runs/{}", 200, {"id": "r3", "status": "timed_out", "exit_code": 124, "duration_ms": 9})
    res = make(api, sleeps).sandboxes.run("sb-1", ["sleep", "9"], on_stdout=lambda _d: None)
    assert (res.run_id, res.exit_code, res.timed_out, res.duration_ms, res.streamed) == ("r3", 124, True, 9, True)


def test_run_with_a_result_answer_delivers_it_once(api: MockServer, sleeps: list[float]) -> None:
    api.json("POST", "/api/v1/sandbox/instances/{}/exec", 200, {"run_id": "a", "exit_code": 0, "stdout": "x", "stderr": ""})
    out: list[str] = []
    res = make(api, sleeps).sandboxes.run("sb-1", ["true"], on_stdout=out.append)
    assert res.streamed is False and out == ["x"] and len(api.requests) == 1


def test_logs_error_event(api: MockServer, sleeps: list[float]) -> None:
    api.on(
        "GET",
        "/api/v1/sandbox/instances/{}/logs",
        lambda _r, reply: reply.sse(
            [("chunk", {"chunk_index": 0, "stream": "stdout", "data": "a"}), ("error", {"code": "dlp_unavailable", "message": "scan failed"})]
        ),
    )
    got: list[str] = []
    with pytest.raises(ServerError) as info:
        for chunk in make(api, sleeps).sandboxes.logs("sb-1", "r1"):
            got.append(chunk.data)
    assert got == ["a"] and info.value.code == "dlp_unavailable"


def test_logs_resume_after_drop(api: MockServer, sleeps: list[float]) -> None:
    calls = iter(range(10))

    def logs(req: Recorded, reply: Reply) -> None:
        if next(calls) == 0:
            reply.sse([("chunk", {"chunk_index": 4, "stream": "stdout", "data": "a"})])  # ends without "done"
            return
        assert req.query["from_chunk"] == "5"
        reply.sse([("chunk", {"chunk_index": 5, "stream": "stdout", "data": "b"}), ("done", {})])

    api.on("GET", "/api/v1/sandbox/instances/{}/logs", logs)
    assert [c.data for c in make(api, sleeps).sandboxes.logs("sb-1", "r1")] == ["a", "b"]


# --- workspaces and build hosts -----------------------------------------------------------

WS = {"id": "ws-1", "name": "dev", "status": "stopped", "health": "healthy"}
BUILD = {"id": "b-1", "workspace_id": "ws-1", "state": "pending", "desired_state": "running", "build_number": 2}
CONNECT = {"ssh_host": "ws-1.ws.sandscale.dev", "ssh_command": "sandscale ssh dev", "ssh_ready": True, "links": []}
LEASE = {"id": "l-1", "pool_id": "p-1", "state": "active", "workspace_id": "ws-1", "size": {"name": "small"}}


def test_workspaces(api: MockServer, sleeps: list[float]) -> None:
    api.json("GET", f"/api/v1/orgs/{ORG}/workspaces", 200, {"workspaces": [WS], "next_cursor": "n"})
    api.json("GET", f"/api/v1/orgs/{ORG}/workspaces/{{}}", 200, WS)
    api.json("POST", f"/api/v1/orgs/{ORG}/workspaces/{{}}/start", 202, BUILD)
    api.json("POST", f"/api/v1/orgs/{ORG}/workspaces/{{}}/stop", 202, {**BUILD, "desired_state": "stopped"})
    api.json("GET", f"/api/v1/orgs/{ORG}/workspaces/{{}}/connect", 200, CONNECT)
    c = make(api, sleeps, region_urls={"us": api.url})
    result = c.workspaces.list(region="us", limit=5, all=True)
    assert (result.data[0].id, result.data[0].region, result.pages[0].next_cursor) == ("ws-1", "us", "n")
    assert api.requests[0].query == {"limit": "5", "all": "true"}
    assert c.workspaces.get("ws-1").status == "stopped"
    started = c.workspaces.start("ws-1")
    assert (started.state, started.desired_state, started.build_number) == ("pending", "running", 2)
    assert c.workspaces.stop("ws-1").desired_state == "stopped"
    info = c.workspaces.connect_info("ws-1")
    assert (info.ssh_host, info.ssh_ready) == ("ws-1.ws.sandscale.dev", True)


def test_build_hosts(api: MockServer, sleeps: list[float]) -> None:
    api.json("GET", f"/api/v1/orgs/{ORG}/build/pools", 200, {"pools": [{"id": "p-1", "name": "linux", "backend": "keystone_cloud", "sizes": [{"name": "small"}]}]})
    api.json("GET", f"/api/v1/orgs/{ORG}/build/leases", 200, {"leases": [LEASE]})
    api.json("POST", f"/api/v1/orgs/{ORG}/build/pools/{{}}/leases", 201, {**LEASE, "state": "provisioning"})
    api.json("POST", f"/api/v1/orgs/{ORG}/build/leases/{{}}/release", 200, {**LEASE, "state": "released"})
    api.json("GET", f"/api/v1/orgs/{ORG}/build/leases/{{}}", 200, LEASE)
    api.json("GET", f"/api/v1/orgs/{ORG}/workspaces/{{}}/connect", 200, CONNECT)
    c = make(api, sleeps, region_urls={"us": api.url})
    assert c.build_hosts.list_pools(region="us").data[0].sizes == ["small"]
    assert c.build_hosts.list(region="us", scope="mine").data[0].id == "l-1"
    started = c.build_hosts.start("p-1", size="small", ttl_seconds=3600, purpose="ci")
    assert api.requests[2].json() == {"size": "small", "ttl_seconds": 3600, "purpose": "ci"}
    assert started.state == "provisioning"
    assert c.build_hosts.stop("l-1").state == "released"
    info = c.build_hosts.connect_info("l-1")
    assert info.kind == "workspace" and info.workspace is not None and info.workspace.ssh_host == "ws-1.ws.sandscale.dev"


def test_build_hosts_lab_and_certificate(api: MockServer, sleeps: list[float]) -> None:
    lab = {"id": "l-2", "pool_id": "p", "state": "active", "workspace_id": None, "lab_host_id": "h-1", "host": {"ssh_user": "nib-1", "ready": True}}
    cert = {"certificate": "ssh-ed25519-cert-v01@openssh.com AAA", "serial": "1", "key_id": "k", "principals": ["nib-1"], "valid_before": "2026-11-17T01:00:00Z", "ssh": {"user": "nib-1"}}
    api.json("GET", f"/api/v1/orgs/{ORG}/build/leases/{{}}", 200, lab)
    api.json("POST", f"/api/v1/orgs/{ORG}/build/leases/{{}}/ssh/certificate", 200, cert)
    c = make(api, sleeps)
    info = c.build_hosts.connect_info("l-2")
    assert (info.kind, info.ssh_relay_path, info.ssh_user) == ("lab", f"/api/v1/orgs/{ORG}/build/leases/l-2/ssh", "nib-1")
    got = c.build_hosts.ssh_certificate("l-2", "ssh-ed25519 AAAA me")
    assert api.requests[1].json() == {"public_key": "ssh-ed25519 AAAA me"}
    assert (got.serial, got.principals, got.ssh) == ("1", ["nib-1"], {"user": "nib-1"})


# --- Sandscale regions ------------------------------------------------------


def _recording(urls: list[str]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if request.url.path == "/api/v1/regions":
            return httpx.Response(
                200,
                json={"regions": [{"id": "us1", "status": "live", "api_url": "https://api.us1.region.example.test"}, {"id": "eu1", "status": "coming_soon"}]},
            )
        return httpx.Response(200, json={"data": [], "id": "sb", "status": "running"})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_sandscale_regions_use_their_own_hosts() -> None:
    urls: list[str] = []
    c = Sandscale(api_key="k", http_client=_recording(urls))
    c.sandboxes.get("sb", region="eu")
    c.sandboxes.get("sb", region="us1")
    c.sandboxes.get("sb")
    assert urls == [
        "https://api.eu.sandscale.dev/api/v1/sandbox/instances/sb",
        "https://api.us.sandscale.dev/api/v1/sandbox/instances/sb",
        "https://api.sandscale.dev/api/v1/sandbox/instances/sb",
    ]
    with pytest.raises(RegionError) as info:
        c.sandboxes.get("sb", region="ap")
    assert info.value.code == "region_unknown"


def test_sandscale_lists_live_regions_through_their_hosts() -> None:
    urls: list[str] = []
    result = Sandscale(api_key="k", http_client=_recording(urls)).sandboxes.list()
    assert [p.region for p in result.pages] == ["us"]
    assert urls == ["https://api.sandscale.dev/api/v1/regions", "https://api.us.sandscale.dev/api/v1/sandbox/instances"]
    assert not any("region.example.test" in u for u in urls)


def test_wrong_region_stays_typed() -> None:
    body = {"code": "wrong_region", "region": "eu1", "error": {"code": "wrong_region", "message": "m", "region": "eu1"}}
    client = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(401, json=body)))
    with pytest.raises(RegionError) as info:
        Sandscale(api_key="k", http_client=client).sandboxes.get("sb", region="us")
    assert info.value.region == "eu1"
