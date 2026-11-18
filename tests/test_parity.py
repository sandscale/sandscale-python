# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""The parity surface: sandbox administration, object storage, compute and account services."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Iterator

import pytest

from sandscale import (
    CreatedAccessKey,
    DefaultRetention,
    EntitlementError,
    LifecycleRule,
    NoncurrentVersionExpiration,
    NotFoundError,
    PermissionDeniedError,
    SandboxWakingError,
    Sandscale,
    ServerError,
    ServiceUnavailableError,
    verify_webhook_signature,
)

from .mock_server import MockServer, error_body

ORG = "org-1"


@pytest.fixture()
def api() -> Iterator[MockServer]:
    server = MockServer()
    yield server
    server.stop()


@pytest.fixture()
def c(api: MockServer) -> Iterator[Sandscale]:
    client = Sandscale(api_key="ssk_test", base_url=api.url, org_id=ORG, region="us", region_urls={"us": api.url})
    client.transport.sleep = lambda _s: None
    yield client
    client.close()


def binary(_req: Any, reply: Any) -> None:
    h = reply._h
    h.send_response(200)
    h.send_header("Content-Type", "application/octet-stream")
    h.send_header("Content-Length", "3")
    h.end_headers()
    h.wfile.write(b"\x00\x01\x02")


def last(api: MockServer) -> Any:
    return api.requests[-1]


# --- sandboxes ------------------------------------------------------------------------------


def test_create_sends_network_image_runtime_environment(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/sandbox/instances", 201, {"id": "sb", "status": "starting"})
    c.sandboxes.create(network="allowlist", image="reg/x@sha256:abc", runtime="firecracker", environment_id="env-1")
    assert last(api).json() == {"network": "allowlist", "image": "reg/x@sha256:abc", "runtime": "firecracker", "environment_id": "env-1"}


def test_ports_and_preview_links(api: MockServer, c: Sandscale) -> None:
    expo = {"id": "e1", "instance_id": "sb", "port": 8080, "protocol": "tcp", "status": "open", "created_by": "u",
            "expires_at": "2026-11-18T01:00:00Z", "connect_path": "/p", "subprotocol": "keystone-port-forward.v1"}
    api.json("POST", "/api/v1/sandbox/instances/{}/ports", 201, expo)
    api.json("GET", "/api/v1/sandbox/instances/{}/ports", 200, {"ports": [expo]})
    api.json("DELETE", "/api/v1/sandbox/instances/{}/ports/{}", 204)
    link = {"id": "l1", "instance_id": "sb", "exposure_id": "e1", "port": 8080, "visibility": "team", "url": "https://x.preview.test/", "status": "active"}
    api.json("POST", "/api/v1/sandbox/instances/{}/ports/{}/preview-links", 201, link)
    api.json("GET", "/api/v1/sandbox/instances/{}/preview-links", 200, {"preview_links": [link]})
    api.json("DELETE", "/api/v1/sandbox/instances/{}/preview-links/{}", 204)

    e = c.sandboxes.expose_port("sb", 8080, ttl_seconds=600)
    assert last(api).json() == {"port": 8080, "ttl_seconds": 600}
    assert (e.id, e.port, e.connect_path, e.region) == ("e1", 8080, "/p", "us")
    assert e.expires_at == datetime(2026, 11, 18, 1, tzinfo=timezone.utc)
    assert [p.id for p in c.sandboxes.list_ports("sb")] == ["e1"]
    c.sandboxes.close_port("sb", 8080)
    assert last(api).path == "/api/v1/sandbox/instances/sb/ports/8080" and last(api).method == "DELETE"
    pl = c.sandboxes.create_preview_link("sb", 8080, visibility="team", ttl_seconds=300)
    assert last(api).path == "/api/v1/sandbox/instances/sb/ports/8080/preview-links"
    assert last(api).json() == {"visibility": "team", "ttl_seconds": 300}
    assert pl.url == "https://x.preview.test/" and pl.visibility == "team"
    assert [x.id for x in c.sandboxes.list_preview_links("sb")] == ["l1"]
    c.sandboxes.revoke_preview_link("sb", "l1")
    assert last(api).path == "/api/v1/sandbox/instances/sb/preview-links/l1"


def test_ssh(api: MockServer, c: Sandscale) -> None:
    info = {"host": "h", "user": "sandbox", "known_hosts": "h ssh-ed25519 AAA", "host_key_sha256": "SHA256:x",
            "certificate_path": "/c", "connect_path": "/s", "subprotocol": "keystone-ssh.v1", "cert_ttl_seconds": 600}
    api.json("GET", "/api/v1/sandbox/instances/{}/ssh", 200, info)
    api.json("POST", "/api/v1/sandbox/instances/{}/ssh/certificate", 200, {**info, "certificate": "ssh-ed25519-cert-v01@openssh.com AAA", "serial": "7", "key_id": "u:sb:7", "valid_before": "2026-11-18T00:10:00Z"})
    i = c.sandboxes.ssh_info("sb")
    assert (i.host, i.cert_ttl_seconds, i.host_key_sha256) == ("h", 600, "SHA256:x")
    cert = c.sandboxes.ssh_certificate("sb", "ssh-ed25519 AAAA")
    assert last(api).json() == {"public_key": "ssh-ed25519 AAAA"}
    assert (cert.serial, cert.key_id, cert.known_hosts) == ("7", "u:sb:7", "h ssh-ed25519 AAA")
    assert cert.valid_before is not None


# --- snapshots, templates, policy ---------------------------------------------------------


def test_org_snapshots(api: MockServer, c: Sandscale) -> None:
    snap = {"id": "s1", "instance_id": "sb", "status": "ready", "label": "x", "size_bytes": 5}
    api.json("GET", "/api/v1/sandbox/snapshots", 200, {"snapshots": [snap], "usage": {"count": 1, "bytes": 5}})
    api.json("GET", "/api/v1/sandbox/snapshots/{}", 200, snap)
    api.json("DELETE", "/api/v1/sandbox/snapshots/{}", 204)
    res = c.snapshots.list(limit=10)
    assert last(api).query == {"limit": "10"}
    assert [s.id for s in res.data] == ["s1"] and (res.usage.count, res.usage.bytes) == (1, 5)
    assert c.snapshots.get("s1").size_bytes == 5
    c.snapshots.delete("s1")
    assert last(api).method == "DELETE"


def test_templates(api: MockServer, c: Sandscale) -> None:
    t = {"id": "t1", "name": "py", "version": "0.1.0", "status": "ready", "disk_size_mb": 2048, "mem_size_mb": 512, "cpu_count": 1}
    api.json("POST", "/api/v1/sandbox/templates", 201, t)
    api.json("GET", "/api/v1/sandbox/templates", 200, {"data": [t], "has_more": False})
    api.json("GET", "/api/v1/sandbox/templates/{}", 200, t)
    api.json("DELETE", "/api/v1/sandbox/templates/{}", 204)
    api.json("GET", "/api/v1/sandbox/templates/{}/build-status", 200, {"status": "building", "progress_percent": 50})
    made = c.templates.create(name="py", image="r/x@sha256:1", disk_mb=2048, memory_mb=512, cpu_count=1)
    assert last(api).json() == {"name": "py", "image": "r/x@sha256:1", "disk_size_mb": 2048, "mem_size_mb": 512, "cpu_count": 1}
    assert made.mem_size_mb == 512
    assert [x.id for x in c.templates.list().data] == ["t1"]
    assert c.templates.get("t1").name == "py"
    c.templates.delete("t1")
    st = c.templates.build_status("t1")
    assert (st.status, st.progress_percent) == ("building", 50)


def test_policy(api: MockServer, c: Sandscale) -> None:
    pol = {"max_concurrent": 5, "max_exec_time_sec": 60, "max_mem_mb": 1024, "max_cpu": 2, "max_disk_mb": None,
           "egress_allowlist": ["pypi.org"], "allowed_providers": [], "egress_presets": ["npm"], "hibernation": "default"}
    api.json("GET", "/api/v1/sandbox/policy", 200, pol)
    api.json("PUT", "/api/v1/sandbox/policy", 200, pol)
    got = c.policy.get()
    assert (got.max_exec_time_seconds, got.max_memory_mb, got.max_disk_mb) == (60, 1024, None)
    assert got.egress_allowlist == ["pypi.org"] and got.egress_presets == ["npm"] and got.hibernation == "default"
    c.policy.set(max_exec_time_seconds=120, max_memory_mb=2048, egress_allowlist=["a.test"], egress_presets=[])
    assert last(api).json() == {"max_exec_time_sec": 120, "max_mem_mb": 2048, "egress_allowlist": ["a.test"], "egress_presets": []}
    c.policy.set(hibernation="off")
    assert last(api).json() == {"hibernation": "off"}


# --- webhooks --------------------------------------------------------------------------------


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhooks_and_secret_is_hidden(api: MockServer, c: Sandscale) -> None:
    wh = {"id": "w1", "url": "https://h.test/x", "events": ["run.completed"], "active": True}
    api.json("POST", "/api/v1/sandbox/webhooks", 201, {**wh, "secret": "whsec_supersecret", "secret_shown_once": True})
    api.json("GET", "/api/v1/sandbox/webhooks", 200, {"webhooks": [{**wh, "secret": "********"}]})
    api.json("DELETE", "/api/v1/sandbox/webhooks/{}", 204)
    created = c.webhooks.create(url="https://h.test/x", events=["run.completed"])
    assert last(api).json() == {"url": "https://h.test/x", "events": ["run.completed"]}
    assert created.secret == "whsec_supersecret"
    assert "supersecret" not in repr(created) and "supersecret" not in str(created.raw)
    assert "secret" not in created.raw
    listed = c.webhooks.list()
    assert [w.id for w in listed] == ["w1"] and not hasattr(listed[0], "secret")
    c.webhooks.delete("w1")
    assert last(api).path == "/api/v1/sandbox/webhooks/w1"


def test_verify_webhook_signature() -> None:
    body = b'{"id":"d1","type":"run.completed"}'
    good = sign(body, "s3cret")
    assert verify_webhook_signature(good, body, "s3cret")
    assert verify_webhook_signature(good, body.decode(), "s3cret")
    assert not verify_webhook_signature(good, body + b" ", "s3cret")  # tampered body
    assert not verify_webhook_signature(good, body, "other")  # wrong secret
    assert not verify_webhook_signature(good.replace("sha256=", "sha1="), body, "s3cret")  # malformed
    assert not verify_webhook_signature("sha256=zz", body, "s3cret")
    assert not verify_webhook_signature("", body, "s3cret")
    assert not verify_webhook_signature(None, body, "s3cret")
    assert not verify_webhook_signature(good, body, "")


def test_verify_is_on_the_service(c: Sandscale) -> None:
    body = b"{}"
    assert c.webhooks.verify(sign(body, "k"), body, "k")


# --- traces ----------------------------------------------------------------------------------


TID = "4bf92f3577b34da6a3ce929d0e0e4736"


def test_traces(api: MockServer, c: Sandscale) -> None:
    summary = {"trace_id": TID, "start_time": "2026-11-18T00:00:00Z", "end_time": "2026-11-18T00:00:02Z", "duration_ms": 2000,
               "spans": 2, "errors": 0, "sandboxes": ["sb"], "vcpu_hours": 0.5, "usd": 0.01, "status": "ok"}
    span = {"trace_id": TID, "span_id": "s1", "kind": "command", "name": "ls", "status": "ok", "duration_ms": 5, "audit_entry_id": "a1",
            "command": {"run_id": "r", "argv": ["ls"], "exit_code": 0, "output_bytes": 3}, "files": [{"path": "/workspace/a", "sha256": "ab", "size_bytes": 1}],
            "box": {"sandbox_id": "sb", "vcpu": 1, "memory_mb": 512}, "cost": {"vcpu_hours": 0.1, "usd": 0.002}, "dlp_rules": ["k"]}
    api.json("GET", "/api/v1/sandbox/traces", 200, {"data": [summary], "has_more": False})
    api.json("GET", "/api/v1/sandbox/traces/{}", 200, {**summary, "span_list": [span], "hidden_spans": 1, "events": [{"id": "e", "source": "s", "type": "t", "severity": "info"}]})
    export = {"enabled": True, "protocol": "otlp_http", "endpoint": "https://otel.test", "header_names": ["DD-API-KEY"], "state": "active", "exported_spans": 9}
    api.json("GET", "/api/v1/sandbox/trace-export", 200, export)
    api.json("PUT", "/api/v1/sandbox/trace-export", 200, export)
    api.json("DELETE", "/api/v1/sandbox/trace-export", 204)
    api.json("POST", "/api/v1/sandbox/trace-export/test", 200, {"ok": False, "error": "endpoint_rejected"})
    res = c.traces.list(sandbox_id="sb", from_=datetime(2026, 11, 17, tzinfo=timezone.utc), limit=5)
    assert last(api).query["sandbox_id"] == "sb" and last(api).query["limit"] == "5" and last(api).query["from"].startswith("2026-11-17")
    assert res.data[0].trace_id == TID and res.data[0].vcpu_hours == 0.5
    tr = c.traces.get(TID)
    assert tr.hidden_spans == 1 and tr.span_list[0].command is not None and tr.span_list[0].command.argv == ["ls"]
    assert tr.span_list[0].cost.usd == 0.002 and tr.span_list[0].box.vcpu == 1 and tr.span_list[0].files[0].sha256 == "ab" and tr.events[0].source == "s"
    ex = c.traces.get_export()
    assert ex.header_names == ["DD-API-KEY"] and ex.exported_spans == 9
    c.traces.set_export(protocol="otlp_http", endpoint="https://otel.test", headers={"DD-API-KEY": "k"}, enabled=True)
    assert last(api).json() == {"protocol": "otlp_http", "endpoint": "https://otel.test", "headers": {"DD-API-KEY": "k"}, "enabled": True}
    c.traces.delete_export()
    test = c.traces.test_export()
    assert test.ok is False and test.error == "endpoint_rejected"


# --- objects ---------------------------------------------------------------------------------


BUCKET = {"Name": "b1", "Region": "us1", "Versioning": "Enabled", "ObjectLock": False, "Encryption": "sse", "Tags": {"a": "b"},
          "HasPolicy": False, "CreatedAt": "2026-11-18T00:00:00Z", "Endpoints": {"PathStyle": "https://o.test/b1", "SigningRegion": "us1"}}


def test_buckets(api: MockServer, c: Sandscale) -> None:
    for action in ("CreateBucket", "DescribeBucket", "UpdateBucket"):
        api.json("POST", f"/api/v1/svc/objects/{action}", 200, BUCKET)
    api.json("POST", "/api/v1/svc/objects/ListBuckets", 200, {"Buckets": [BUCKET], "NextToken": "n"})
    api.json("POST", "/api/v1/svc/objects/DeleteBucket", 200, {})
    b = c.objects.create_bucket("b1", versioning="Enabled", object_lock=True, default_retention=DefaultRetention("GOVERNANCE", 7), tags={"a": "b"}, client_token="tok")
    assert last(api).path == "/api/v1/svc/objects/CreateBucket"
    assert last(api).json() == {"Name": "b1", "Versioning": "Enabled", "ObjectLock": True, "DefaultRetention": {"Mode": "GOVERNANCE", "Days": 7}, "Tags": {"a": "b"}, "ClientToken": "tok"}
    assert (b.name, b.versioning, b.tags, b.endpoints.path_style, b.endpoints.signing_region) == ("b1", "Enabled", {"a": "b"}, "https://o.test/b1", "us1")
    lst = c.objects.list_buckets(max_results=5)
    assert last(api).json() == {"MaxResults": 5} and lst.next_token == "n" and lst.buckets[0].name == "b1"
    assert c.objects.get_bucket("b1").name == "b1" and last(api).json() == {"Name": "b1"}
    c.objects.update_bucket("b1", presign=True, clear_default_retention=True)
    assert last(api).json() == {"Name": "b1", "ClearDefaultRetention": True, "Presign": True}
    c.objects.delete_bucket("b1")
    assert last(api).path == "/api/v1/svc/objects/DeleteBucket"


def test_lifecycle_and_policy(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/svc/objects/PutBucketLifecycle", 200, {})
    api.json("POST", "/api/v1/svc/objects/GetBucketLifecycle", 200, {"Rules": [{"ID": "r", "Status": "Enabled", "Prefix": "tmp/", "Expiration": {"Days": 3}}]})
    api.json("POST", "/api/v1/svc/objects/DeleteBucketLifecycle", 200, {})
    api.json("POST", "/api/v1/svc/objects/PutBucketPolicy", 200, {})
    api.json("POST", "/api/v1/svc/objects/GetBucketPolicy", 200, {"Policy": "{}"})
    api.json("POST", "/api/v1/svc/objects/DeleteBucketPolicy", 200, {})
    c.objects.put_lifecycle("b1", [LifecycleRule(id="r", prefix="tmp/", expiration_days=3, noncurrent_version_expiration=NoncurrentVersionExpiration(1), abort_incomplete_multipart_upload_days=2)])
    assert last(api).json() == {"Name": "b1", "Rules": [{"ID": "r", "Status": "Enabled", "Prefix": "tmp/", "Expiration": {"Days": 3},
                                                          "NoncurrentVersionExpiration": {"NoncurrentDays": 1}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2}}]}
    rules = c.objects.get_lifecycle("b1")
    assert rules[0].expiration_days == 3 and rules[0].prefix == "tmp/"
    c.objects.delete_lifecycle("b1")
    c.objects.put_policy("b1", {"Version": "1"})
    assert last(api).json() == {"Name": "b1", "Policy": '{"Version": "1"}'}
    c.objects.put_policy("b1", "{}")
    assert last(api).json()["Policy"] == "{}"
    assert c.objects.get_policy("b1") == "{}"
    c.objects.delete_policy("b1")
    assert last(api).path == "/api/v1/svc/objects/DeleteBucketPolicy"


def test_access_keys_secret_returned_once_and_never_in_repr(api: MockServer, c: Sandscale) -> None:
    key = {"AccessKeyId": "AK1", "Principal": "p", "Description": "ci", "Status": "Active", "Permissions": ["read"], "Buckets": ["b1"], "Prefixes": [], "CIDRs": []}
    api.json("POST", "/api/v1/svc/objects/CreateAccessKey", 200, {"AccessKey": key, "SecretAccessKey": "SECRET-VALUE-123"})
    api.json("POST", "/api/v1/svc/objects/ListAccessKeys", 200, {"AccessKeys": [key], "CanManageAll": True})
    api.json("POST", "/api/v1/svc/objects/UpdateAccessKey", 200, {})
    api.json("POST", "/api/v1/svc/objects/DeleteAccessKey", 200, {})
    created = c.objects.create_access_key(description="ci", expires_in_days=30, permissions=["read"], buckets=["b1"])
    assert last(api).json() == {"Description": "ci", "ExpiresInDays": 30, "Permissions": ["read"], "Buckets": ["b1"]}
    assert isinstance(created, CreatedAccessKey) and created.secret_access_key == "SECRET-VALUE-123"
    assert "SECRET-VALUE" not in repr(created) and "SECRET-VALUE" not in str(created.access_key.raw)
    assert created.access_key.access_key_id == "AK1"
    keys = c.objects.list_access_keys(all=True)
    assert last(api).json() == {"All": True} and keys[0].buckets == ["b1"]
    c.objects.update_access_key("AK1", "Inactive")
    assert last(api).json() == {"AccessKeyId": "AK1", "Status": "Inactive"}
    c.objects.delete_access_key("AK1")
    assert last(api).json() == {"AccessKeyId": "AK1"}


def test_objects_limits(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/svc/objects/DescribeObjectsLimits", 200, {"Enabled": True, "Region": "us1", "Quotas": [{"QuotaCode": "q", "Name": "n", "Value": 5, "Used": 1}], "Features": {"presign": {"Available": False, "Reason": "plan"}}})
    lim = c.objects.limits()
    assert lim.enabled and lim.quotas[0]["used"] == 1 and lim.features["presign"] == {"available": False, "reason": "plan"}


# --- workspaces ------------------------------------------------------------------------------


def test_workspace_lifecycle(api: MockServer, c: Sandscale) -> None:
    ws = {"id": "w1", "name": "dev", "status": "stopped"}
    build = {"id": "b1", "workspace_id": "w1", "state": "pending"}
    api.json("POST", "/api/v1/orgs/{}/workspaces", 201, {"workspace": ws, "build": build})
    api.json("PATCH", "/api/v1/orgs/{}/workspaces/{}", 200, {**ws, "name": "dev2"})
    api.json("DELETE", "/api/v1/orgs/{}/workspaces/{}", 204)
    api.json("POST", "/api/v1/orgs/{}/workspaces/{}/rebuild", 202, build)
    w, b = c.workspaces.create(name="dev", template_id="t", parameters={"a": "b"}, repository="github.com/o/r")
    assert last(api).path == f"/api/v1/orgs/{ORG}/workspaces"
    assert last(api).json() == {"name": "dev", "template_id": "t", "parameters": {"a": "b"}, "repository": "github.com/o/r"}
    assert (w.id, b.id) == ("w1", "b1")
    up = c.workspaces.update("w1", name="dev2", idle_timeout_seconds=600)
    assert last(api).method == "PATCH" and last(api).json() == {"name": "dev2", "idle_timeout_seconds": 600} and up.name == "dev2"
    c.workspaces.rebuild("w1", template_version_id="v2")
    assert last(api).json() == {"template_version_id": "v2"}
    c.workspaces.delete("w1")
    assert last(api).method == "DELETE" and last(api).path.endswith("/workspaces/w1")


def test_workspace_open_backups_apps(api: MockServer, c: Sandscale) -> None:
    api.json("GET", "/api/v1/orgs/{}/workspaces/{}/open", 200, {"ide": "vscode", "kind": "deeplink", "url": "vscode://x", "ssh_host": "h", "folder": "/home", "requires": ["config-ssh"]})
    backup = {"id": "bk1", "workspace_id": "w1", "type": "snapshot", "status": "completed", "size": 10, "checksum": "ab"}
    api.json("GET", "/api/v1/orgs/{}/workspaces/{}/backups", 200, {"backups": [backup], "count": 1})
    api.json("POST", "/api/v1/orgs/{}/workspaces/{}/backups", 201, backup)
    api.json("POST", "/api/v1/orgs/{}/backups/{}/verify", 200, {"backup_id": "bk1", "valid": True, "checksum_match": True, "verified_at": "2026-11-18T00:00:00Z"})
    app = {"slug": "web", "display_name": "Web", "port": 3000, "share": "owner", "effective_share": "owner", "can_open": True, "share_levels": ["owner", "org"]}
    api.json("GET", "/api/v1/orgs/{}/workspaces/{}/apps", 200, {"apps": [app], "policy": {}})
    api.json("PATCH", "/api/v1/orgs/{}/workspaces/{}/apps/{}/share", 200, {"slug": "web", "share": "org", "effective_share": "members"})
    link = c.workspaces.open_link("w1", "vscode")
    assert last(api).query == {"ide": "vscode"} and link.url == "vscode://x" and link.requires == ["config-ssh"]
    assert [b.id for b in c.workspaces.list_backups("w1", limit=5)] == ["bk1"] and last(api).query == {"limit": "5"}
    assert c.workspaces.create_backup("w1").checksum == "ab"
    v = c.workspaces.verify_backup("bk1")
    assert v.valid and v.checksum_match and v.verified_at is not None
    apps = c.workspaces.list_apps("w1")
    assert apps[0].slug == "web" and apps[0].can_open and apps[0].share_levels == ["owner", "org"]
    out = c.workspaces.share_app("w1", "web", "org")
    assert last(api).method == "PATCH" and last(api).json() == {"share": "org"} and (out.slug, out.share, out.effective_share) == ("web", "org", "members")


# --- build hosts, lab hosts, agent cloud -----------------------------------------------------


def test_build_host_lease_operations(api: MockServer, c: Sandscale) -> None:
    lease = {"id": "l1", "pool_id": "p", "state": "active"}
    api.json("POST", "/api/v1/orgs/{}/build/leases/{}/renew", 200, lease)
    api.json("POST", "/api/v1/orgs/{}/build/leases/{}/kill", 200, {**lease, "state": "ended"})
    run = {"id": "r1", "lease_id": "l1", "argv": ["make"], "command": "make", "state": "completed", "exit_code": 0, "duration_ms": 5}
    api.json("GET", "/api/v1/orgs/{}/build/leases/{}/runs", 200, {"runs": [run]})
    api.json("GET", "/api/v1/orgs/{}/build/leases/{}/runs/{}", 200, run)
    art = {"id": "a1", "lease_id": "l1", "name": "out.tgz", "size_bytes": 3, "sha256": "ab"}
    api.json("GET", "/api/v1/orgs/{}/build/leases/{}/artifacts", 200, {"artifacts": [art]})
    api.json("GET", "/api/v1/orgs/{}/build/leases/{}/artifacts/{}", 200, art)
    api.on("GET", "/api/v1/orgs/{}/build/leases/{}/artifacts/{}/content", binary)
    api.json("DELETE", "/api/v1/orgs/{}/build/leases/{}/artifacts/{}", 204)
    caches = {"caches": [{"name": "npm", "scope": "pool", "max_bytes": 100, "used_bytes": 7, "entries": [{"id": "c1", "cache": "npm", "key": "k", "scope": "pool", "size_bytes": 7, "sha256": "ab"}]}]}
    api.json("GET", "/api/v1/orgs/{}/build/leases/{}/caches", 200, caches)
    api.json("GET", "/api/v1/orgs/{}/build/pools/{}/caches", 200, caches)
    api.json("DELETE", "/api/v1/orgs/{}/build/pools/{}/caches/{}", 204)
    assert c.build_hosts.renew("l1", 3600).id == "l1" and last(api).json() == {"ttl_seconds": 3600}
    assert c.build_hosts.kill("l1", reason="abuse").state == "ended" and last(api).json() == {"reason": "abuse"}
    assert c.build_hosts.list_runs("l1")[0].exit_code == 0
    assert c.build_hosts.get_run("l1", "r1").argv == ["make"]
    assert c.build_hosts.list_artifacts("l1")[0].name == "out.tgz"
    assert c.build_hosts.get_artifact("l1", "a1").size_bytes == 3
    assert c.build_hosts.download_artifact("l1", "a1") == b"\x00\x01\x02"
    c.build_hosts.delete_artifact("l1", "a1")
    assert last(api).method == "DELETE"
    cv = c.build_hosts.list_caches("l1")[0]
    assert (cv.name, cv.scope, cv.max_bytes, cv.used_bytes) == ("npm", "pool", 100, 7) and cv.entries[0].cache == "npm"
    assert c.build_hosts.list_pool_caches("p")[0].entries[0].key == "k"
    c.build_hosts.purge_pool_cache("p", "npm")
    assert last(api).path == f"/api/v1/orgs/{ORG}/build/pools/p/caches/npm"


def test_lab_hosts(api: MockServer, c: Sandscale) -> None:
    host = {"id": "h1", "name": "mac", "status": "online", "labels": {"os": "mac"}, "pool_ids": ["p"], "max_leases": 2, "disabled": False, "active_leases": 1}
    api.json("GET", "/api/v1/orgs/{}/build/lab-hosts", 200, {"lab_hosts": [host]})
    api.json("GET", "/api/v1/orgs/{}/build/lab-hosts/{}", 200, host)
    api.json("POST", "/api/v1/orgs/{}/build/lab-hosts/{}/revoke", 200, {**host, "status": "revoked"})
    assert c.lab_hosts.list().data[0].labels == {"os": "mac"}
    assert c.lab_hosts.get("h1").max_leases == 2
    assert c.lab_hosts.revoke("h1", reason="lost").status == "revoked" and last(api).json() == {"reason": "lost"}


def test_agent_cloud_tasks(api: MockServer, c: Sandscale) -> None:
    task = {"id": "t1", "lead_grant_id": "g", "state": "queued", "engine": "claude_code", "repository": "r"}
    api.json("POST", "/api/v1/orgs/{}/build/leads/{}/tasks", 201, task)
    api.json("GET", "/api/v1/orgs/{}/build/leads/{}/tasks", 200, {"tasks": [task]})
    api.json("GET", "/api/v1/orgs/{}/build/leads/{}/tasks/{}", 200, task)
    api.json("POST", "/api/v1/orgs/{}/build/leads/{}/tasks/{}/stop", 200, {**task, "state": "cancelled"})
    t = c.agent_cloud.create_task(repository="r", brief="fix the bug", engine="claude_code", target="pool", pool_id="p", max_runtime_seconds=600)
    assert last(api).path == f"/api/v1/orgs/{ORG}/build/leads/current/tasks"
    assert last(api).json() == {"repository": "r", "brief": "fix the bug", "engine": "claude_code", "target": "pool", "pool_id": "p", "max_runtime_seconds": 600}
    assert t.state == "queued"
    assert c.agent_cloud.list_tasks(state="open", grant_id="g1").data[0].id == "t1"
    assert last(api).query == {"state": "open"} and "/leads/g1/tasks" in last(api).path
    assert c.agent_cloud.get_task("t1").engine == "claude_code"
    assert c.agent_cloud.cancel_task("t1").state == "cancelled" and last(api).path.endswith("/leads/current/tasks/t1/stop")


# --- account ---------------------------------------------------------------------------------


def test_billing_usage_regions(api: MockServer, c: Sandscale) -> None:
    offer = {"plan": "pro", "name": "Pro", "monthly_minor": 2500, "included_vcpu_hours": 750, "overage_allowed": True, "features": ["workspaces"]}
    state = {"plan": "pro", "interval": "month", "paid_seats": 1, "overage_enabled": False, "cancel_at_period_end": False, "pending_plan": "free"}
    api.json("GET", "/api/v1/orgs/{}/sandscale/billing", 200, {"state": state, "offer": offer, "balance": {"month": "2026-11", "used_vcpu_hours": "1.5"}, "plans": [offer]})
    api.json("POST", "/api/v1/orgs/{}/sandscale/billing/plan", 200, {"state": {**state, "plan": "team"}, "offer": offer})
    api.json("PUT", "/api/v1/orgs/{}/sandscale/billing/overage", 200, {"state": {**state, "overage_enabled": True}, "offer": offer})
    api.json("DELETE", "/api/v1/orgs/{}/sandscale/billing/plan/pending", 200, {"state": {**state, "pending_plan": None}})
    api.json("POST", "/api/v1/orgs/{}/sandscale/billing/checkout", 201, {"id": "cs", "url": "https://pay.test/cs", "plan": "pro", "interval": "month", "seats": 1})
    api.json("GET", "/api/v1/sandscale/usage", 200, {"month": "2026-11", "vcpu_seconds_used": 10, "vcpu_seconds_left": 90, "running_boxes": 2, "running_by_region": {"us1": 2}})
    api.json("GET", "/api/v1/regions", 200, {"regions": [{"id": "us1", "status": "live", "api_url": "https://api.us.sandscale.dev"}]})
    b = c.account.billing()
    assert last(api).path == f"/api/v1/orgs/{ORG}/sandscale/billing"
    assert (b.state.plan, b.state.pending_plan, b.offer.monthly_minor, b.balance.used_vcpu_hours, len(b.plans)) == ("pro", "free", 2500, "1.5", 1)
    assert c.account.change_plan(plan="team", interval="month", seats=3).plan == "team"
    assert last(api).json() == {"plan": "team", "interval": "month", "seats": 3}
    assert c.account.set_overage(True).overage_enabled is True and last(api).json() == {"enabled": True}
    assert c.account.cancel_pending_plan_change().pending_plan is None
    co = c.account.checkout(plan="pro", interval="month")
    assert co.url == "https://pay.test/cs" and last(api).json() == {"plan": "pro", "interval": "month"}
    u = c.account.usage()
    assert (u.vcpu_seconds_used, u.running_by_region) == (10, {"us1": 2})
    assert c.account.regions()[0].id == "us1"


def test_api_keys_secret_never_in_repr(api: MockServer, c: Sandscale) -> None:
    view = {"id": "k1", "name": "ci", "key_prefix": "ssk_ab", "scopes": ["sandbox"], "expires_at": "2026-12-01T00:00:00Z", "state": "active", "created_at": "2026-11-18T00:00:00Z"}
    api.json("GET", "/api/v1/account/api-keys", 200, {"api_keys": [view], "limits": {"max_days": 90, "max_active": 5}})
    api.json("POST", "/api/v1/account/api-keys", 201, {**view, "key": "ssk_FULLSECRETVALUE"})
    api.json("POST", "/api/v1/account/api-keys/{}/rotate", 200, {**view, "id": "k2", "key": "ssk_ROTATEDSECRET", "rotated_from": "k1", "previous_expires_at": "2026-11-18T00:01:00Z"})
    api.json("DELETE", "/api/v1/account/api-keys/{}", 204)
    lst = c.account.list_api_keys()
    assert lst.api_keys[0].key_prefix == "ssk_ab" and (lst.limits.max_days, lst.limits.max_active) == (90, 5)
    made = c.account.create_api_key(name="ci", scopes=["sandbox"], expires_at=datetime(2026, 12, 1, tzinfo=timezone.utc))
    assert last(api).json() == {"name": "ci", "scopes": ["sandbox"], "expires_at": "2026-12-01T00:00:00+00:00"}
    assert made.key == "ssk_FULLSECRETVALUE" and "FULLSECRET" not in repr(made) and "FULLSECRET" not in str(made.raw)
    rot = c.account.rotate_api_key("k1", overlap_seconds=60)
    assert last(api).json() == {"overlap_seconds": 60} and rot.rotated_from == "k1" and "ROTATEDSECRET" not in repr(rot)
    assert rot.previous_expires_at is not None
    c.account.delete_api_key("k1")
    assert last(api).method == "DELETE" and last(api).path == "/api/v1/account/api-keys/k1"


# --- errors ----------------------------------------------------------------------------------


def test_sandbox_waking_is_a_retryable_typed_error(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/sandbox/instances/{}/exec", 503, error_body("sandbox_waking", "resuming"), {"Retry-After": "2"})
    with pytest.raises(SandboxWakingError) as e:
        c.sandboxes.run("sb", ["true"])
    assert isinstance(e.value, ServiceUnavailableError) and isinstance(e.value, ServerError)
    assert e.value.retryable and e.value.retry_after == 2.0 and e.value.code == "sandbox_waking"
    assert len(api.requests) == 1  # a command is never retried by the SDK


def test_safe_calls_retry_sandbox_waking(api: MockServer, c: Sandscale) -> None:
    replies = iter([(503, error_body("sandbox_waking", "resuming")), (200, {"id": "sb", "status": "running"})])

    def handler(_r: Any, reply: Any) -> None:
        status, body = next(replies)
        reply.json(status, body, {"Retry-After": "1"} if status == 503 else None)

    api.on("GET", "/api/v1/sandbox/instances/{}", handler)
    assert c.sandboxes.get("sb").status == "running" and len(api.requests) == 2


@pytest.mark.parametrize("code", ["feature_not_in_plan", "network_not_in_plan", "lease_not_in_plan", "public_preview_not_in_plan", "overage_not_in_plan"])
def test_not_in_plan_is_entitlement(api: MockServer, c: Sandscale, code: str) -> None:
    api.json("POST", "/api/v1/sandbox/instances", 403, error_body(code, "upgrade"))
    with pytest.raises(EntitlementError) as e:
        c.sandboxes.create()
    assert e.value.code == code


def test_entitlement_unavailable_is_retryable_unavailable(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/sandbox/instances", 503, error_body("entitlement_unavailable", "stale"))
    with pytest.raises(ServiceUnavailableError) as e:
        c.sandboxes.create()
    assert not isinstance(e.value, EntitlementError) and e.value.retryable


def test_any_503_and_person_required(api: MockServer, c: Sandscale) -> None:
    api.json("GET", "/api/v1/sandbox/traces", 503, error_body("dlp_unavailable", "x"))
    with pytest.raises(ServiceUnavailableError):
        c.traces.list()
    api.json("POST", "/api/v1/orgs/{}/build/leads/{}/tasks", 403, error_body("person_required", "use a person token"))
    with pytest.raises(PermissionDeniedError):
        c.agent_cloud.create_task(repository="r", brief="b", engine="codex")
    api.json("GET", "/api/v1/sandbox/templates/{}", 404, error_body("template_not_found", "no"))
    with pytest.raises(NotFoundError):
        c.templates.get("x")


def test_plain_500_is_not_retryable() -> None:
    from sandscale.errors import error_for

    e = error_for(500, "internal", "x")
    assert isinstance(e, ServerError) and not isinstance(e, ServiceUnavailableError) and not e.retryable


# --- keep_awake and prepare ------------------------------------------------------------------


def test_keep_awake_retries_a_waking_sandbox(api: MockServer, c: Sandscale) -> None:
    waits: list[float] = []
    c.transport.sleep = waits.append
    replies = iter([(503, error_body("sandbox_waking", "resuming")), (200, {"id": "sb", "keep_awake": True, "ttl_seconds": 60})])

    def handler(_r: Any, reply: Any) -> None:
        status, body = next(replies)
        reply.json(status, body, {"Retry-After": "2"} if status == 503 else None)

    api.on("POST", "/api/v1/sandbox/instances/{}/keep-awake", handler)
    assert c.sandboxes.keep_awake("sb", 60, reason="waiting")["keep_awake"] is True
    assert len(api.requests) == 2 and waits == [2.0]
    assert last(api).json() == {"ttl_seconds": 60, "reason": "waiting"}


def test_keep_awake_raises_waking_after_its_retries(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/sandbox/instances/{}/keep-awake", 503, error_body("sandbox_waking", "resuming"), {"Retry-After": "1"})
    with pytest.raises(SandboxWakingError):
        c.sandboxes.keep_awake("sb", 60)
    assert len(api.requests) == 4


def test_prepare_never_raises_for_a_waking_sandbox(api: MockServer, c: Sandscale) -> None:
    api.json("POST", "/api/v1/sandbox/instances/{}/prepare", 503, error_body("sandbox_waking", "resuming"))
    c.sandboxes.prepare("sb")
    assert len(api.requests) == 1
