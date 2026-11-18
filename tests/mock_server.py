# Copyright 2026 Neural Inverse
# SPDX-License-Identifier: Apache-2.0
"""A local HTTP server that answers like the Sandscale API, for the SDK's tests."""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit


@dataclass
class Recorded:
    method: str
    path: str
    #: The route pattern that answered, e.g. "GET /api/v1/sandbox/instances/{}".
    route: str
    query: dict[str, str]
    headers: dict[str, str]
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class Reply:
    """What a handler answers with."""

    def __init__(self, handler: BaseHTTPRequestHandler) -> None:
        self._h = handler

    def json(self, status: int, body: Any = None, headers: Optional[dict[str, str]] = None) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self._h.send_response(status)
        self._h.send_header("Content-Type", "application/json")
        self._h.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self._h.send_header(k, v)
        self._h.end_headers()
        self._h.wfile.write(data)

    def sse(self, events: list[tuple[str, Any]], end: bool = True) -> None:
        self._h.send_response(200)
        self._h.send_header("Content-Type", "text/event-stream")
        self._h.send_header("Connection", "close")
        self._h.end_headers()
        for event, data in events:
            self._h.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
            self._h.wfile.flush()
        self._h.close_connection = True


Handler = Callable[[Recorded, Reply], None]


class MockServer:
    def __init__(self) -> None:
        self.requests: list[Recorded] = []
        self._routes: list[tuple[str, str, re.Pattern[str], Handler]] = []
        mock = self

        class _H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                url = urlsplit(self.path)
                method = self.command
                found = next((r for r in mock._routes if r[0] == method and r[2].fullmatch(url.path)), None)
                rec = Recorded(
                    method=method,
                    path=url.path,
                    route=f"{method} {found[1]}" if found else f"{method} {url.path} (unrouted)",
                    query={k: v[0] for k, v in parse_qs(url.query).items()},
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                )
                mock.requests.append(rec)
                if found is None:
                    Reply(self).json(404, {"error": {"code": "not_found", "message": f"no mock for {method} {url.path}"}})
                    return
                found[3](rec, Reply(self))

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        self._server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self._thread.start()

    def on(self, method: str, pattern: str, handler: Handler) -> "MockServer":
        """Registers a handler; "{}" matches one path segment. Later registrations win."""
        regex = re.compile(re.escape(pattern).replace(r"\{\}", "[^/]+"))
        self._routes.insert(0, (method, pattern, regex, handler))
        return self

    def json(self, method: str, pattern: str, status: int, body: Any = None, headers: Optional[dict[str, str]] = None) -> "MockServer":
        return self.on(method, pattern, lambda _req, reply: reply.json(status, body, headers))

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": "req-1", **extra}}
