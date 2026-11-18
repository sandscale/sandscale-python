<!-- Copyright 2026 Neural Inverse -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# sandscale

Python SDK for [Sandscale](https://sandscale.dev): sandboxes, workspaces and build hosts over
the Sandscale API (`https://api.sandscale.dev`). One dependency (`httpx`); Python 3.10 or later.

The server decides everything: permissions, plan limits, quotas, entitlements, kill switches
and regions. The SDK sends your request as you (your API key or your own sign-in token) and
hands back the server's answer, including its error code and message.

```bash
pip install sandscale
```

Documentation: https://sandscale.dev/docs. Source and issues: https://github.com/sandscale/sandscale-python. Licensed under Apache-2.0.

## Quick start

```python
import sys
from sandscale import Sandscale

with Sandscale() as sandscale:  # SANDSCALE_API_KEY from the environment
    box = sandscale.sandboxes.create(template="builtin:python", timeout_seconds=600)
    try:
        run = sandscale.sandboxes.run(
            box.id,
            'python -c "print(6*7)"',
            region=box.region,
            on_stdout=sys.stdout.write,
            on_stderr=sys.stderr.write,
        )
        print("exit code", run.exit_code)
    finally:
        sandscale.sandboxes.stop(box.id, region=box.region)
```

## Authentication

| Argument | Environment | |
|---|---|---|
| `api_key` | `SANDSCALE_API_KEY` | A Sandscale API key. |
| `token` | | The person's own sign-in access token, or a function returning a current one (called before every request, so it can refresh). |
| `org_id` | `SANDSCALE_ORG_ID` | Sent as `X-Org-ID`; required by workspace and build host calls, whose routes name the organization. |
| `base_url` | `SANDSCALE_BASE_URL` | Default `https://api.sandscale.dev`. `https` only (plain `http` only to a loopback host). |

Credentials are held in memory and sent only to the configured API origin and the region
origins the server lists; redirects are not followed, so a credential never follows one.

## Regions

One account works in every Sandscale region. Pass `region="us"` or `region="eu"` to the client
(the default for every call) or to any call:

| Region | API |
|---|---|
| none | `https://api.sandscale.dev`, the front door: it routes to the request's region, US by default |
| `"us"` | `https://api.us.sandscale.dev` |
| `"eu"` | `https://api.eu.sandscale.dev` (when Sandscale opens in eu1) |

A region id such as `us1` names the same region. `region_urls` sets origins explicitly.
Against another `base_url` (a self-hosted Keystone) a region is looked up in that server's
public region list (`GET /api/v1/regions`).

Models carry the `region` they were read from; pass it to later calls on them. Lists without a
region read every Sandscale region the front door reports live and merge the results; `pages`
says, per region, the next cursor or the error that region answered.

## API

| Area | Methods |
|---|---|
| `sandboxes` | `create` (`network`, `image`, `runtime`, `environment_id`), `get`, `list`, `run` (live stdout and stderr, exit code), `logs`, `write_file`, `read_file`, `list_files`, `pause`, `resume`, `snapshot`, `list_snapshots`, `stop`, `expose_port`, `list_ports`, `close_port`, `create_preview_link`, `list_preview_links`, `revoke_preview_link`, `ssh_info`, `ssh_certificate` |
| `snapshots` | `list` (with quota usage), `get`, `delete` |
| `templates` | `create`, `list`, `get`, `delete`, `build_status` |
| `policy` | `get`, `set` |
| `webhooks` | `list`, `create`, `delete`, `verify` (also `verify_webhook_signature`) |
| `traces` | `list`, `get`, `get_export`, `set_export`, `delete_export`, `test_export` |
| `objects` | buckets (`create_bucket`, `list_buckets`, `get_bucket`, `update_bucket`, `delete_bucket`), lifecycle, policy, access keys, `limits` |
| `workspaces` | `list`, `get`, `start`, `stop`, `connect_info`, `create`, `update`, `delete`, `rebuild`, `open_link`, `list_backups`, `create_backup`, `verify_backup`, `list_apps`, `share_app` |
| `build_hosts` | `list_pools`, `list`, `get`, `start` (take a lease of a pool), `stop` (release it), `connect_info`, `ssh_certificate`, `renew`, `kill`, `list_runs`, `get_run`, `list_artifacts`, `get_artifact`, `download_artifact`, `delete_artifact`, `list_caches`, `list_pool_caches`, `purge_pool_cache` |
| `lab_hosts` | `list`, `get`, `revoke` |
| `agent_cloud` | `create_task`, `list_tasks`, `get_task`, `cancel_task` |
| `account` | `billing`, `change_plan`, `set_overage`, `cancel_pending_plan_change`, `checkout`, `usage`, `regions`, `list_api_keys`, `create_api_key`, `rotate_api_key`, `delete_api_key` |

`sandboxes.run` waits for the command and returns a `RunResult` (`run_id`, `exit_code`,
`stdout`, `stderr`, `duration_ms`, `oom_killed`, `timed_out`, `streamed`). With `on_stdout` /
`on_stderr` it starts the command without waiting (`wait` false): the server answers with the
run's id, and the output arrives live, in the calling thread, from that run's log stream, after
the organization's DLP rules. The server may redact it, or end the stream with
`dlp_unavailable`, raised as a `ServerError`. The exit code comes from the stream's end. A
server that answers with the finished result instead gets the callbacks the final output once.

`sandboxes.create(vault_env=[VaultEnvRef("DB_PASSWORD", "secret/data/db", "password")])` puts
Keystone Vault values in the sandbox's environment. The server reads them as you and gives them
to the sandbox only.

## More examples

Every call takes `region=` like the first ones. The server decides what you may do; the SDK
only carries the answer.

### Ports, preview links and SSH

```python
box = sandscale.sandboxes.create(template="builtin:python", network="allowlist", runtime="firecracker")
port = sandscale.sandboxes.expose_port(box.id, 8080, ttl_seconds=3600, region=box.region)
link = sandscale.sandboxes.create_preview_link(box.id, 8080, visibility="team", region=box.region)
print(link.url)
sandscale.sandboxes.revoke_preview_link(box.id, link.id, region=box.region)
sandscale.sandboxes.close_port(box.id, 8080, region=box.region)

cert = sandscale.sandboxes.ssh_certificate(box.id, open("id_ed25519.pub").read().strip(), region=box.region)
print(cert.known_hosts, cert.key_id)  # the certificate itself is in cert.certificate
```

### Snapshots, templates and policy

```python
snaps = sandscale.snapshots.list()
print(snaps.usage.count, snaps.usage.bytes)

tpl = sandscale.templates.create(name="py-ml", image="registry.example/py-ml@sha256:" + "0" * 64, memory_mb=2048)
print(sandscale.templates.build_status(tpl.id).status)

sandscale.policy.set(egress_allowlist=["pypi.org"], egress_presets=["npm", "pypi"], max_concurrent=10)
```

`policy.set(hibernation="on" | "off" | "default")` sets hibernation between tool calls;
`keep_awake` retries a waking sandbox (`SandboxWakingError`) before raising.

### Webhooks

```python
from sandscale import verify_webhook_signature

hook = sandscale.webhooks.create(url="https://example.com/hooks/sandscale", events=["run.completed"])
signing_secret = hook.secret  # shown once: store it in your secret manager, never print it

# In your receiver: pass the raw body exactly as received.
ok = verify_webhook_signature(request.headers.get("X-Keystone-Signature"), raw_body, signing_secret)
```

The signature is `sha256=` and the hex HMAC-SHA256 of the raw body under the secret; the check
is constant time. Current signing carries no timestamp. Test, redeliver and the delivery log
are not served yet.

### Run traces and OpenTelemetry export

```python
for t in sandscale.traces.list(limit=10).data:
    print(t.trace_id, t.status, t.spans)
trace = sandscale.traces.get(t.trace_id)
sandscale.traces.set_export(protocol="otlp_http", endpoint="https://otel.example.com", headers={"x-honeycomb-team": api_key_for_collector})
print(sandscale.traces.test_export().ok)
```

### Object storage

```python
from sandscale import LifecycleRule

sandscale.objects.create_bucket("artifacts", versioning="Enabled")
sandscale.objects.put_lifecycle("artifacts", [LifecycleRule(id="tmp", prefix="tmp/", expiration_days=7)])
created = sandscale.objects.create_access_key(description="ci", buckets=["artifacts"], expires_in_days=30)
key_id = created.access_key.access_key_id
secret = created.secret_access_key  # shown once, not in repr(); store it, never log it
```

### Workspaces, build hosts and lab hosts

```python
ws, build = sandscale.workspaces.create(name="dev", template_id="tpl-1", repository="github.com/acme/app")
print(sandscale.workspaces.open_link(ws.id, "vscode").url)
backup = sandscale.workspaces.create_backup(ws.id)
print(sandscale.workspaces.verify_backup(backup.id).valid)
sandscale.workspaces.share_app(ws.id, "web", "org")

lease = sandscale.build_hosts.renew("lease-1", 3600)
for artifact in sandscale.build_hosts.list_artifacts(lease.id):
    data = sandscale.build_hosts.download_artifact(lease.id, artifact.id)
print(sandscale.build_hosts.list_pool_caches("pool-1").used_bytes)
sandscale.lab_hosts.revoke("host-1", reason="decommissioned")
```

### Agent Cloud tasks

```python
task = sandscale.agent_cloud.create_task(repository="github.com/acme/app", brief="Fix the flaky test", engine="claude_code")
print(sandscale.agent_cloud.get_task(task.id).state)
sandscale.agent_cloud.cancel_task(task.id)
```

These are Keystone's lead routes (never the device agent). They need a signed-in person's
`token`; an API key is refused with 403 `person_required`.

### Account

```python
billing = sandscale.account.billing()
print(billing.state.plan, billing.balance.remaining_vcpu_hours)
sandscale.account.set_overage(True)          # the server decides whether the plan allows it
sandscale.account.change_plan(plan="team", interval="month", seats=3)
print(sandscale.account.usage().running_boxes, [r.id for r in sandscale.account.regions()])

from datetime import datetime, timedelta, timezone
key = sandscale.account.create_api_key(name="ci", expires_at=datetime.now(timezone.utc) + timedelta(days=30))
new_key = key.key  # shown once; store it, never print it
sandscale.account.rotate_api_key(key.id, overlap_seconds=300)
sandscale.account.delete_api_key(key.id)
```

Plan changes, overage and personal API keys need a signed-in person's token. Secrets the server
shows once (webhook signing secret, `secret_access_key`, API key `key`) are fields excluded from
`repr` and from `raw`; the SDK never logs or prints them.

## Errors

Every API error is a `SandscaleError` with the server's `status`, `code`, `message`,
`request_id` and `details`: `InvalidRequestError` (400, 413, 422), `AuthenticationError` (401),
`PermissionDeniedError` (403), `NotFoundError` (404), `ConflictError` (409),
`LimitExceededError` (402 or a quota or limit code) and its `RateLimitError` (429, with
`retry_after`), `EntitlementError` (`not_entitled`, `payment_required`, `entitlement_*`,
`plan_*`, `*_not_in_plan`), `RegionError` (`wrong_region` with `region`, `region_*`), `KillSwitchError`
(`kill_switch_*`), `ServerError` (5xx; `retryable` for 502, 503 and 504) with `ServiceUnavailableError` (any 503, with
`retry_after`; also `entitlement_unavailable`) and `SandboxWakingError` (503 `sandbox_waking`: the
sandbox is resuming, retry after `retry_after`), and `APIConnectionError` (no answer).
`ConfigurationError` is raised before any request when the client cannot be configured safely.

## Retries

Only safe calls (`GET`) are retried, at most `max_retries` times (default 2), after a
connection error, 429, 502, 503 or 504, with exponential backoff and full jitter (at most 8 s),
or the server's `Retry-After` (at most 60 s). Kill switch, entitlement and region refusals are
never retried. Calls that change something are sent once.

## Known gaps

- **Cross-region credentials.** Until the global plane syncs API keys and sign-in sessions to
  every region, a credential of one region is refused in another with `wrong_region`
  (`RegionError`, with `region`).
- **Vault environment on sandboxes** needs a server that supports `vault_env`. A server from before it ignores the
  field.
- Synchronous client only; an asyncio client is a follow-up.

## Tests

```bash
pip install -e ".[dev]" && pytest   # unit tests against a local mock server, route contract
SANDSCALE_API_KEY=... pytest         # also the integration test (starts and stops one sandbox)
```

`tests/test_routes.py` fails when the server stops mounting a route this SDK calls (checked against the
server route inventory when the tests run inside the Keystone source tree, skipped elsewhere) or when the SDK calls a route it does not list.
