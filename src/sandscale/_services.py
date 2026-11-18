# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Sandboxes, workspaces and build hosts."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable, Iterator, List, Mapping, Optional, Sequence, TypeVar, Union

from ._transport import Transport, seg
from .errors import SandboxWakingError, SandscaleError, ServerError
from .admin_models import (
    AppShareResult,
    BackupVerification,
    CacheView,
    LeaseArtifact,
    LeaseRun,
    OpenLink,
    PortExposure,
    PreviewLink,
    SandboxSshCertificate,
    SandboxSshInfo,
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
    parse_time,
)

T = TypeVar("T")
Raw = dict[str, Any]
# keep_awake retries a sandbox that is still waking this often, waiting at most this long each time.
_WAKING_RETRIES = 3
_WAKING_MAX_WAIT = 10.0
Callback = Callable[[str], None]

# The server waits for the command up to its timeout plus a 30 s worker margin.
_EXEC_MARGIN = 30.0
_LOG_RECONNECTS = 3


def list_across_regions(
    t: Transport, region: Optional[str], one: Callable[[Optional[str]], tuple[list[T], RegionPage]]
) -> ListResult[T]:
    """One list call per live region (or the named one), merged."""
    named = t.region_of(region)
    if named is not None:
        data, page = one(named)
        return ListResult(data=data, pages=[page])
    try:
        regions: list[Optional[str]] = list(t.live_regions())
    except SandscaleError:
        regions = []
    if not regions:
        regions = [None]  # a single-region installation
    out: ListResult[T] = ListResult()
    for r in regions:
        try:
            data, page = one(r)
        except SandscaleError as e:
            out.pages.append(RegionPage(region=r, error=e))
            continue
        out.data.extend(data)
        out.pages.append(page)
    if all(p.error is not None for p in out.pages):
        error = out.pages[0].error
        assert error is not None
        raise error
    return out


def _b64(data: Union[bytes, str]) -> str:
    return base64.b64encode(data.encode() if isinstance(data, str) else data).decode("ascii")


class Sandboxes:
    def __init__(self, t: Transport) -> None:
        self._t = t

    def create(
        self,
        *,
        template: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        cpu_count: Optional[int] = None,
        memory_mb: Optional[int] = None,
        disk_mb: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
        env: Optional[Mapping[str, str]] = None,
        vault_env: Optional[Sequence[Union[VaultEnvRef, Mapping[str, str]]]] = None,
        command: Optional[Sequence[str]] = None,
        name: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        metadata: Optional[Mapping[str, str]] = None,
        network: Optional[str] = None,
        image: Optional[str] = None,
        runtime: Optional[str] = None,
        environment_id: Optional[str] = None,
        region: Optional[str] = None,
    ) -> Sandbox:
        """Starts a sandbox. Limits, entitlement and policy are decided by the server.

        ``vault_env`` names Keystone Vault values for the sandbox's environment
        (``VaultEnvRef(name, path, field)`` or a mapping with those keys). The server reads each
        as the caller and hands it to the sandbox only: values never pass through the SDK.

        ``network`` is the network mode (``none``, or ``allowlist`` where the plan has network),
        ``image`` an OCI image pinned by digest (``name@sha256:...``) on a worker that runs
        images of its own, ``runtime`` ``firecracker`` (or another runtime where allowed) and
        ``environment_id`` a cloud environment the launch options list."""
        fields = {
            "template_id": template,
            "snapshot_id": snapshot_id,
            "cpu_count": cpu_count,
            "mem_mb": memory_mb,
            "disk_mb": disk_mb,
            "ttl_seconds": timeout_seconds,
            "env": dict(env) if env is not None else None,
            "vault_env": [_vault_ref(r) for r in vault_env] if vault_env is not None else None,
            "command": list(command) if command is not None else None,
            "name": name,
            "labels": dict(labels) if labels is not None else None,
            "metadata": dict(metadata) if metadata is not None else None,
            "network": network,
            "image": image,
            "runtime": runtime,
            "environment_id": environment_id,
        }
        body = {k: v for k, v in fields.items() if v is not None}
        raw = self._t.request("POST", "/api/v1/sandbox/instances", region=region, json_body=body)
        return Sandbox.from_raw(raw, self._t.region_of(region))

    def get(self, sandbox_id: str, *, region: Optional[str] = None) -> Sandbox:
        raw = self._t.request("GET", f"/api/v1/sandbox/instances/{seg(sandbox_id)}", region=region)
        return Sandbox.from_raw(raw, self._t.region_of(region))

    def list(
        self,
        *,
        status: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        region: Optional[str] = None,
    ) -> ListResult[Sandbox]:
        """Lists sandboxes: of one region when one is named, else of every live region."""

        def one(r: Optional[str]) -> tuple[list[Sandbox], RegionPage]:
            query = {"status": status, "project_id": project_id, "limit": limit, "cursor": cursor}
            raw = self._t.request("GET", "/api/v1/sandbox/instances", region=r, query=query)
            data = [Sandbox.from_raw(s, r) for s in raw.get("data") or []]
            return data, RegionPage(region=r, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"))

        return list_across_regions(self._t, region, one)

    def stop(self, sandbox_id: str, *, region: Optional[str] = None) -> None:
        """Stops the sandbox and releases it."""
        self._t.request("DELETE", f"/api/v1/sandbox/instances/{seg(sandbox_id)}", region=region)

    def pause(self, sandbox_id: str, *, region: Optional[str] = None) -> Raw:
        """Pauses a microVM sandbox (409 pause_unsupported for a container sandbox)."""
        result: Raw = self._t.request("POST", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/pause", region=region)
        return result

    def resume(self, sandbox_id: str, *, region: Optional[str] = None) -> Raw:
        result: Raw = self._t.request("POST", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/resume", region=region)
        return result

    def keep_awake(
        self, sandbox_id: str, ttl_seconds: int, *, reason: Optional[str] = None, region: Optional[str] = None
    ) -> Raw:
        """Keeps the sandbox from hibernating between tool calls for ``ttl_seconds`` (0 clears it).

        A sandbox idle between two calls is hibernated (memory compressed in RAM) and woken by the
        next call; use this for a box that must stay awake. ``reason`` is shown to people who ask.
        """
        body: Raw = {"ttl_seconds": ttl_seconds}
        if reason:
            body["reason"] = reason
        # Idempotent: a 503 ``sandbox_waking`` is retried a few times after Retry-After.
        for attempt in range(_WAKING_RETRIES + 1):
            try:
                result: Raw = self._t.request(
                    "POST", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/keep-awake", region=region, json_body=body
                )
                return result
            except SandboxWakingError as e:
                if attempt >= _WAKING_RETRIES:
                    raise
                self._t.sleep(min(e.retry_after, _WAKING_MAX_WAIT) if e.retry_after > 0 else 0.5 * 2**attempt)
        raise AssertionError("unreachable")

    def prepare(self, sandbox_id: str, *, region: Optional[str] = None) -> None:
        """Optional "about to call" hint: a hibernated sandbox starts waking early.

        Fire-and-forget: it never raises (``SandboxWakingError`` included) and never waits for the wake; skipping it only changes the
        latency of the next call.
        """
        try:
            self._t.request("POST", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/prepare", region=region, timeout=2.0)
        except Exception:  # a hint: whatever goes wrong, the call itself wakes the sandbox
            pass

    def snapshot(self, sandbox_id: str, *, label: Optional[str] = None, region: Optional[str] = None) -> Snapshot:
        """Snapshots the sandbox's /workspace; start from it with ``create(snapshot_id=...)``."""
        body = {"label": label} if label is not None else None
        raw = self._t.request(
            "POST", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/snapshot", region=region, json_body=body
        )
        return Snapshot.from_raw(raw, self._t.region_of(region))

    def list_snapshots(self, sandbox_id: str, *, region: Optional[str] = None) -> List[Snapshot]:
        raw = self._t.request("GET", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/snapshots", region=region)
        # The server answers {"snapshots": [...]}.
        return [Snapshot.from_raw(s, self._t.region_of(region)) for s in raw.get("snapshots") or []]

    def run(
        self,
        sandbox_id: str,
        command: Union[str, Sequence[str]],
        *,
        env: Optional[Mapping[str, str]] = None,
        workdir: Optional[str] = None,
        timeout: int = 60,
        stdin: Union[bytes, str, None] = None,
        on_stdout: Optional[Callback] = None,
        on_stderr: Optional[Callback] = None,
        region: Optional[str] = None,
    ) -> RunResult:
        """Runs a command and returns its exit code and output.

        With ``on_stdout`` or ``on_stderr`` the command is started without waiting (``wait``
        false): the server answers with its run id at once, and the output is delivered live, in
        this thread, from that run's log stream; the exit code comes from the stream's end. A
        server that answers with the finished result instead (a server before ``wait``, or a
        sandbox without live output) gets the callbacks the final output once (``streamed``
        False)."""
        argv = ["sh", "-c", command] if isinstance(command, str) else list(command)
        body: Raw = {"command": argv, "timeout_sec": timeout}
        if env is not None:
            body["env"] = dict(env)
        if workdir is not None:
            body["workdir"] = workdir
        if stdin is not None:
            body["stdin"] = _b64(stdin)
        live = on_stdout is not None or on_stderr is not None
        if live:
            body["wait"] = False
        raw: Raw = self._t.request(
            "POST",
            f"/api/v1/sandbox/instances/{seg(sandbox_id)}/exec",
            region=region,
            json_body=body,
            timeout=timeout + _EXEC_MARGIN,
        )
        if not live or "exit_code" in raw:
            result = _run_result(raw, str(raw.get("stdout") or ""), str(raw.get("stderr") or ""), False)
            if live:
                if result.stdout and on_stdout is not None:
                    on_stdout(result.stdout)
                if result.stderr and on_stderr is not None:
                    on_stderr(result.stderr)
            return result
        # 202: the run is queued; its output and end come from its log stream.
        run_id = str(raw.get("run_id") or "")
        out = {"stdout": "", "stderr": ""}
        ends: list[RunEnd] = []
        for chunk in self.logs(sandbox_id, run_id, region=region, on_done=ends.append):
            out[chunk.stream] += chunk.data
            callback = on_stderr if chunk.stream == "stderr" else on_stdout
            if callback is not None:
                callback(chunk.data)
        final: Raw = ends[0].raw if ends else {}
        if not ends or ends[0].exit_code is None:
            # A server whose stream end carries no result: read the run.
            final = self._t.request("GET", f"/api/v1/sandbox/runs/{seg(run_id)}", region=region)
        return _run_result({**final, "run_id": run_id}, out["stdout"], out["stderr"], True)

    def logs(
        self,
        sandbox_id: str,
        run_id: str,
        *,
        from_chunk: Optional[int] = None,
        region: Optional[str] = None,
        on_done: Optional[Callable[[RunEnd], None]] = None,
    ) -> Iterator[OutputChunk]:
        """Streams a run's output (Server-Sent Events), resuming after a dropped connection.
        ``on_done`` receives how the run ended, from the stream's done event."""
        path = f"/api/v1/sandbox/instances/{seg(sandbox_id)}/logs"
        reconnects = 0
        while True:
            done = False
            event, data = "message", []
            try:
                for line in self._t.stream_lines(path, region=region, query={"run_id": run_id, "from_chunk": from_chunk}):
                    if line.startswith("event:"):
                        event = line[6:].strip()
                    elif line.startswith("data:"):
                        data.append(line[5:].removeprefix(" "))
                    elif line == "" and data:
                        payload = _json_object("\n".join(data))
                        kind, event, data = event, "message", []
                        if kind == "done":
                            done = True
                            if on_done is not None:
                                on_done(RunEnd.from_raw(run_id, payload))
                            break
                        if kind == "error":
                            # The server withheld the rest (its DLP scan failed): never a silent cut.
                            raise ServerError(
                                503,
                                str(payload.get("code") or "stream_error"),
                                str(payload.get("message") or "the output stream ended with an error"),
                            )
                        if kind == "chunk" and isinstance(payload.get("data"), str):
                            index = int(payload.get("chunk_index") or 0)
                            from_chunk = index + 1
                            stream = "stderr" if payload.get("stream") == "stderr" else "stdout"
                            yield OutputChunk(stream=stream, data=payload["data"], chunk_index=index)
            except SandscaleError as e:
                if e.status != 0 or reconnects >= _LOG_RECONNECTS:
                    raise
            if done:
                return
            if reconnects >= _LOG_RECONNECTS:
                raise ServerError(0, "stream_ended", "the output stream ended before the run did")
            reconnects += 1

    def write_file(
        self, sandbox_id: str, path: str, data: Union[bytes, str], *, mode: Optional[str] = None, region: Optional[str] = None
    ) -> None:
        body: Raw = {"path": path, "content": _b64(data)}
        if mode:
            body["mode"] = mode
        self._t.request("PUT", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/files", region=region, json_body=body)

    def read_file(self, sandbox_id: str, path: str, *, region: Optional[str] = None) -> bytes:
        raw = self._files(sandbox_id, path, region)
        if raw.get("type") != "file":
            raise SandscaleError(400, "not_a_file", f"{path} is not a regular file")
        return base64.b64decode(raw.get("content") or "")

    def list_files(self, sandbox_id: str, path: str, *, region: Optional[str] = None) -> List[FileEntry]:
        raw = self._files(sandbox_id, path, region)
        if raw.get("type") != "dir":
            raise SandscaleError(400, "not_a_directory", f"{path} is not a directory")
        prefix = path if path.endswith("/") else path + "/"
        return [
            FileEntry(name=str(e.get("name")), path=prefix + str(e.get("name")), is_dir=e.get("type") == "dir", size=e.get("size_bytes"))
            for e in raw.get("entries") or []
        ]

    # --- ports, preview links, SSH ---------------------------------------------------------

    def expose_port(
        self, sandbox_id: str, port: int, *, ttl_seconds: Optional[int] = None, region: Optional[str] = None
    ) -> PortExposure:
        """Opens a TCP port of the running sandbox to you alone, through Keystone."""
        body: Raw = {"port": port}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        raw = self._t.request("POST", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/ports", region=region, json_body=body)
        return PortExposure.from_raw(raw, self._t.region_of(region))

    def list_ports(self, sandbox_id: str, *, region: Optional[str] = None) -> List[PortExposure]:
        raw = self._t.request("GET", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/ports", region=region)
        return [PortExposure.from_raw(p, self._t.region_of(region)) for p in raw.get("ports") or []]

    def close_port(self, sandbox_id: str, port: Union[int, str], *, region: Optional[str] = None) -> None:
        """Closes an exposure by its id or port number."""
        self._t.request("DELETE", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/ports/{seg(str(port))}", region=region)

    def create_preview_link(
        self,
        sandbox_id: str,
        port: Union[int, str],
        *,
        visibility: str,
        ttl_seconds: Optional[int] = None,
        region: Optional[str] = None,
    ) -> PreviewLink:
        """Shares your exposed port as a URL on the preview domain (``team`` or ``public``)."""
        body: Raw = {"visibility": visibility}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        raw = self._t.request(
            "POST",
            f"/api/v1/sandbox/instances/{seg(sandbox_id)}/ports/{seg(str(port))}/preview-links",
            region=region,
            json_body=body,
        )
        return PreviewLink.from_raw(raw, self._t.region_of(region))

    def list_preview_links(self, sandbox_id: str, *, region: Optional[str] = None) -> List[PreviewLink]:
        raw = self._t.request("GET", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/preview-links", region=region)
        return [PreviewLink.from_raw(p, self._t.region_of(region)) for p in raw.get("preview_links") or []]

    def revoke_preview_link(self, sandbox_id: str, link_id: str, *, region: Optional[str] = None) -> None:
        self._t.request("DELETE", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/preview-links/{seg(link_id)}", region=region)

    def ssh_info(self, sandbox_id: str, *, region: Optional[str] = None) -> SandboxSshInfo:
        """The host key to trust, the user and the route to connect through."""
        raw = self._t.request("GET", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/ssh", region=region)
        return SandboxSshInfo.from_raw(raw, self._t.region_of(region))

    def ssh_certificate(self, sandbox_id: str, public_key: str, *, region: Optional[str] = None) -> SandboxSshCertificate:
        """A short-lived SSH certificate for this sandbox, for your public key."""
        raw = self._t.request(
            "POST",
            f"/api/v1/sandbox/instances/{seg(sandbox_id)}/ssh/certificate",
            region=region,
            json_body={"public_key": public_key},
        )
        return SandboxSshCertificate.from_raw(raw, self._t.region_of(region))

    def _files(self, sandbox_id: str, path: str, region: Optional[str]) -> Raw:
        raw: Raw = self._t.request(
            "GET", f"/api/v1/sandbox/instances/{seg(sandbox_id)}/files", region=region, query={"path": path}
        )
        return raw


def _vault_ref(ref: Union[VaultEnvRef, Mapping[str, str]]) -> dict[str, str]:
    if isinstance(ref, VaultEnvRef):
        return {"name": ref.name, "path": ref.path, "field": ref.field}
    return {"name": ref["name"], "path": ref["path"], "field": ref["field"]}


def _run_result(raw: Raw, stdout: str, stderr: str, streamed: bool) -> RunResult:
    exit_code = raw.get("exit_code")
    return RunResult(
        run_id=str(raw.get("run_id") or raw.get("id") or ""),
        exit_code=int(exit_code) if isinstance(exit_code, int) else -1,
        stdout=stdout,
        stderr=stderr,
        duration_ms=int(raw.get("duration_ms") or 0),
        oom_killed=raw.get("oom_killed") is True or raw.get("status") == "oom_killed",
        timed_out=raw.get("timed_out") is True or raw.get("status") == "timed_out",
        streamed=streamed,
    )


def _json_object(text: str) -> Raw:
    try:
        value = json.loads(text)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


class Workspaces:
    def __init__(self, t: Transport) -> None:
        self._t = t

    def _org(self) -> str:
        return seg(self._t.require_org())

    def list(
        self,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        all: bool = False,  # noqa: A002 - the API's own name
        region: Optional[str] = None,
    ) -> ListResult[Workspace]:
        """Lists workspaces: of one region when one is named, else of every live region."""

        def one(r: Optional[str]) -> tuple[list[Workspace], RegionPage]:
            query = {"limit": limit, "cursor": cursor, "all": "true" if all else None}
            raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/workspaces", region=r, query=query)
            cursor_out = raw.get("next_cursor") or None
            data = [Workspace.from_raw(w, r) for w in raw.get("workspaces") or []]
            return data, RegionPage(region=r, has_more=cursor_out is not None, next_cursor=cursor_out)

        return list_across_regions(self._t, region, one)

    def get(self, workspace_id: str, *, region: Optional[str] = None) -> Workspace:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}", region=region)
        return Workspace.from_raw(raw, self._t.region_of(region))

    def start(self, workspace_id: str, *, region: Optional[str] = None) -> WorkspaceBuild:
        """Queues a start build."""
        raw = self._t.request("POST", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/start", region=region)
        return WorkspaceBuild.from_raw(raw, self._t.region_of(region))

    def stop(self, workspace_id: str, *, region: Optional[str] = None) -> WorkspaceBuild:
        """Queues a stop build."""
        raw = self._t.request("POST", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/stop", region=region)
        return WorkspaceBuild.from_raw(raw, self._t.region_of(region))

    def create(
        self,
        *,
        name: str,
        template_id: Optional[str] = None,
        template_version_id: Optional[str] = None,
        parameters: Optional[Mapping[str, str]] = None,
        ttl_seconds: Optional[int] = None,
        idle_timeout_seconds: Optional[int] = None,
        autostart_schedule: Optional[str] = None,
        project_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        repository: Optional[str] = None,
        region: Optional[str] = None,
    ) -> tuple[Workspace, WorkspaceBuild]:
        """Creates a workspace and queues its first build; returns both."""
        fields = {
            "name": name,
            "template_id": template_id,
            "template_version_id": template_version_id,
            "parameters": dict(parameters) if parameters is not None else None,
            "ttl_seconds": ttl_seconds,
            "idle_timeout_seconds": idle_timeout_seconds,
            "autostart_schedule": autostart_schedule,
            "project_id": project_id,
            "environment_id": environment_id,
            "repository": repository,
        }
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/workspaces",
            region=region,
            json_body={k: v for k, v in fields.items() if v is not None},
        )
        r = self._t.region_of(region)
        return Workspace.from_raw(raw.get("workspace") or {}, r), WorkspaceBuild.from_raw(raw.get("build") or {}, r)

    def update(
        self,
        workspace_id: str,
        *,
        name: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        idle_timeout_seconds: Optional[int] = None,
        autostart_schedule: Optional[str] = None,
        region: Optional[str] = None,
    ) -> Workspace:
        fields = {
            "name": name,
            "ttl_seconds": ttl_seconds,
            "idle_timeout_seconds": idle_timeout_seconds,
            "autostart_schedule": autostart_schedule,
        }
        raw = self._t.request(
            "PATCH",
            f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}",
            region=region,
            json_body={k: v for k, v in fields.items() if v is not None},
        )
        return Workspace.from_raw(raw, self._t.region_of(region))

    def delete(self, workspace_id: str, *, region: Optional[str] = None) -> None:
        self._t.request("DELETE", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}", region=region)

    def rebuild(
        self,
        workspace_id: str,
        *,
        template_version_id: Optional[str] = None,
        parameters: Optional[Mapping[str, str]] = None,
        region: Optional[str] = None,
    ) -> WorkspaceBuild:
        """Queues a rebuild (optionally on another template version)."""
        body: Raw = {}
        if template_version_id is not None:
            body["template_version_id"] = template_version_id
        if parameters is not None:
            body["parameters"] = dict(parameters)
        raw = self._t.request(
            "POST", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/rebuild", region=region, json_body=body
        )
        return WorkspaceBuild.from_raw(raw, self._t.region_of(region))

    def open_link(self, workspace_id: str, ide: str, *, region: Optional[str] = None) -> OpenLink:
        """The link that opens the workspace in ``ide``, built by the server and only for the IDEs the policy allows."""
        raw = self._t.request(
            "GET", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/open", region=region, query={"ide": ide}
        )
        return OpenLink.from_raw(raw)

    def list_backups(self, workspace_id: str, *, limit: Optional[int] = None, region: Optional[str] = None) -> List[WorkspaceBackup]:
        raw = self._t.request(
            "GET", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/backups", region=region, query={"limit": limit}
        )
        return [WorkspaceBackup.from_raw(b, self._t.region_of(region)) for b in raw.get("backups") or []]

    def create_backup(self, workspace_id: str, *, region: Optional[str] = None) -> WorkspaceBackup:
        raw = self._t.request("POST", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/backups", region=region)
        return WorkspaceBackup.from_raw(raw, self._t.region_of(region))

    def verify_backup(self, backup_id: str, *, region: Optional[str] = None) -> BackupVerification:
        """Checks the backup's integrity (its checksum)."""
        raw = self._t.request("POST", f"/api/v1/orgs/{self._org()}/backups/{seg(backup_id)}/verify", region=region)
        errors = raw.get("errors")
        return BackupVerification(
            backup_id=str(raw.get("backup_id") or ""),
            valid=raw.get("valid") is True,
            checksum_match=raw.get("checksum_match") is True,
            errors=[str(e) for e in errors] if isinstance(errors, list) else [],
            verified_at=parse_time(raw.get("verified_at")),
        )

    def list_apps(self, workspace_id: str, *, region: Optional[str] = None) -> List[WorkspaceApp]:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/apps", region=region)
        return [WorkspaceApp.from_raw(a, self._t.region_of(region)) for a in raw.get("apps") or []]

    def share_app(self, workspace_id: str, slug: str, share: str, *, region: Optional[str] = None) -> AppShareResult:
        """Sets an app's share level (``owner``, ``members``, ``org`` or ``public``); the policy decides."""
        raw: Raw = self._t.request(
            "PATCH",
            f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/apps/{seg(slug)}/share",
            region=region,
            json_body={"share": share},
        ) or {}
        return AppShareResult.from_raw(raw)

    def connect_info(self, workspace_id: str, *, region: Optional[str] = None) -> ConnectInfo:
        """SSH host and command, port forwarding and editor links, as the server allows."""
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/workspaces/{seg(workspace_id)}/connect", region=region)
        return ConnectInfo.from_raw(raw)


class BuildHosts:
    def __init__(self, t: Transport, workspaces: Workspaces) -> None:
        self._t = t
        self._workspaces = workspaces

    def _org(self) -> str:
        return seg(self._t.require_org())

    def list_pools(self, *, region: Optional[str] = None) -> ListResult[Pool]:

        def one(r: Optional[str]) -> tuple[list[Pool], RegionPage]:
            raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/pools", region=r)
            return [Pool.from_raw(p, r) for p in raw.get("pools") or []], RegionPage(region=r)

        return list_across_regions(self._t, region, one)

    def list(
        self,
        *,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        limit: Optional[int] = None,
        region: Optional[str] = None,
    ) -> ListResult[Lease]:
        """The caller's leases (``scope="org"`` for every lease, where the server allows it)."""

        def one(r: Optional[str]) -> tuple[list[Lease], RegionPage]:
            raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/leases", region=r, query={"scope": scope, "state": state, "limit": limit})
            return [Lease.from_raw(item, r) for item in raw.get("leases") or []], RegionPage(region=r)

        return list_across_regions(self._t, region, one)

    def get(self, lease_id: str, *, region: Optional[str] = None) -> Lease:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}", region=region)
        return Lease.from_raw(raw, self._t.region_of(region))

    def start(
        self,
        pool_id: str,
        *,
        size: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        purpose: Optional[str] = None,
        repo: Optional[str] = None,
        region: Optional[str] = None,
    ) -> Lease:
        """Takes a build host lease from a pool (it may wait for approval: ``pending_approval``)."""
        fields = {"size": size, "ttl_seconds": ttl_seconds, "purpose": purpose, "repo": repo}
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/build/pools/{seg(pool_id)}/leases",
            region=region,
            json_body={k: v for k, v in fields.items() if v is not None},
        )
        return Lease.from_raw(raw, self._t.region_of(region))

    def stop(self, lease_id: str, *, region: Optional[str] = None) -> Lease:
        """Releases the lease; the server wipes and deletes its host."""
        raw = self._t.request("POST", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/release", region=region)
        return Lease.from_raw(raw, self._t.region_of(region))

    def renew(self, lease_id: str, ttl_seconds: int, *, region: Optional[str] = None) -> Lease:
        """Extends the lease (the plan's lease hours and the lease's hard maximum still apply)."""
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/renew",
            region=region,
            json_body={"ttl_seconds": ttl_seconds},
        )
        return Lease.from_raw(raw, self._t.region_of(region))

    def kill(self, lease_id: str, *, reason: Optional[str] = None, region: Optional[str] = None) -> Lease:
        """Ends any lease at once (administrators)."""
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/kill",
            region=region,
            json_body={"reason": reason or ""},
        )
        return Lease.from_raw(raw, self._t.region_of(region))

    def list_runs(self, lease_id: str, *, region: Optional[str] = None) -> List[LeaseRun]:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/runs", region=region)
        return [LeaseRun.from_raw(r, self._t.region_of(region)) for r in raw.get("runs") or []]

    def get_run(self, lease_id: str, run_id: str, *, region: Optional[str] = None) -> LeaseRun:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/runs/{seg(run_id)}", region=region)
        return LeaseRun.from_raw(raw, self._t.region_of(region))

    def list_artifacts(self, lease_id: str, *, region: Optional[str] = None) -> List[LeaseArtifact]:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/artifacts", region=region)
        return [LeaseArtifact.from_raw(a, self._t.region_of(region)) for a in raw.get("artifacts") or []]

    def get_artifact(self, lease_id: str, artifact_id: str, *, region: Optional[str] = None) -> LeaseArtifact:
        raw = self._t.request(
            "GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/artifacts/{seg(artifact_id)}", region=region
        )
        return LeaseArtifact.from_raw(raw, self._t.region_of(region))

    def download_artifact(self, lease_id: str, artifact_id: str, *, region: Optional[str] = None) -> bytes:
        """The artifact's content."""
        return self._t.request_bytes(
            "GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/artifacts/{seg(artifact_id)}/content", region=region
        )

    def delete_artifact(self, lease_id: str, artifact_id: str, *, region: Optional[str] = None) -> None:
        self._t.request(
            "DELETE", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/artifacts/{seg(artifact_id)}", region=region
        )

    def list_caches(self, lease_id: str, *, region: Optional[str] = None) -> List[CacheView]:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/caches", region=region)
        return [CacheView.from_raw(c, self._t.region_of(region)) for c in raw.get("caches") or []]

    def list_pool_caches(self, pool_id: str, *, region: Optional[str] = None) -> List[CacheView]:
        raw = self._t.request("GET", f"/api/v1/orgs/{self._org()}/build/pools/{seg(pool_id)}/caches", region=region)
        return [CacheView.from_raw(c, self._t.region_of(region)) for c in raw.get("caches") or []]

    def purge_pool_cache(self, pool_id: str, cache_name: str, *, region: Optional[str] = None) -> None:
        self._t.request(
            "DELETE", f"/api/v1/orgs/{self._org()}/build/pools/{seg(pool_id)}/caches/{seg(cache_name)}", region=region
        )

    def connect_info(self, lease_id: str, *, region: Optional[str] = None) -> LeaseConnectInfo:
        """How to reach the lease's host: its workspace's connect info, or a lab host's SSH relay."""
        lease = self.get(lease_id, region=region)
        if lease.workspace_id:
            return LeaseConnectInfo(
                lease=lease, kind="workspace", workspace=self._workspaces.connect_info(lease.workspace_id, region=region)
            )
        if lease.lab_host_id:
            relay = f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/ssh"
            return LeaseConnectInfo(lease=lease, kind="lab", ssh_relay_path=relay, ssh_user=lease.ssh_user)
        return LeaseConnectInfo(lease=lease, kind="pending")

    def ssh_certificate(self, lease_id: str, public_key: str, *, region: Optional[str] = None) -> SSHCertificate:
        """A short-lived SSH certificate for the lease's host, for your public key."""
        raw = self._t.request(
            "POST",
            f"/api/v1/orgs/{self._org()}/build/leases/{seg(lease_id)}/ssh/certificate",
            region=region,
            json_body={"public_key": public_key},
        )
        return SSHCertificate(
            certificate=str(raw.get("certificate") or ""),
            serial=str(raw.get("serial") or ""),
            key_id=str(raw.get("key_id") or ""),
            principals=list(raw.get("principals") or []),
            ssh=dict(raw.get("ssh") or {}),
            valid_after=parse_time(raw.get("valid_after")),
            valid_before=parse_time(raw.get("valid_before")),
        )
