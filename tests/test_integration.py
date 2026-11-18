# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""Runs against the real Sandscale API only when SANDSCALE_API_KEY is set (it starts and stops
one small sandbox, which uses credits). SANDSCALE_BASE_URL, SANDSCALE_ORG_ID and
SANDSCALE_REGION are honoured. Nothing secret is printed."""

from __future__ import annotations

import os

import pytest

from sandscale import Sandscale

pytestmark = pytest.mark.skipif(not os.environ.get("SANDSCALE_API_KEY"), reason="SANDSCALE_API_KEY is not set")


def test_sandbox_round_trip() -> None:
    with Sandscale(region=os.environ.get("SANDSCALE_REGION") or None) as sandscale:
        box = sandscale.sandboxes.create(template="builtin:base", timeout_seconds=300)
        try:
            out: list[str] = []
            run = sandscale.sandboxes.run(
                box.id, "echo hello && echo oops >&2 && exit 3", region=box.region, on_stdout=out.append, on_stderr=out.append
            )
            assert run.exit_code == 3
            assert "hello" in run.stdout and "hello" in "".join(out)
            sandscale.sandboxes.write_file(box.id, "/workspace/hello.txt", "hi", region=box.region)
            assert sandscale.sandboxes.read_file(box.id, "/workspace/hello.txt", region=box.region) == b"hi"
            assert any(s.id == box.id for s in sandscale.sandboxes.list(region=box.region).data)
        finally:
            sandscale.sandboxes.stop(box.id, region=box.region)
