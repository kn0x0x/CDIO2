from __future__ import annotations

import json
import logging
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from .engine import RuleEngine
from .models import HTTPRequest
from .parsers import dict_to_request, parse_raw_http

logger = logging.getLogger(__name__)


class EventLog:
    """Thread-safe in-memory buffer of recent detection events."""

    def __init__(self, *, max_items: int = 200) -> None:
        self._buffer: deque[Dict[str, Any]] = deque(maxlen=max_items)
        self._lock = Lock()

    def add(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._buffer.appendleft(event)

    def snapshot(self, limit: int | None = None) -> list[Dict[str, Any]]:
        with self._lock:
            items = list(self._buffer)
        if limit is not None:
            return items[:limit]
        return items


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<title>RCE Guard Dashboard</title>
<style>
body { font-family: system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
header { padding: 16px 24px; background: #1e293b; display: flex; justify-content: space-between; align-items: center; }
main { padding: 24px; }
button { background: #38bdf8; border: none; color: #0f172a; padding: 8px 16px; border-radius: 4px; font-weight: 600; cursor: pointer; }
button:hover { background: #0ea5e9; }
.table { width: 100%; border-collapse: collapse; margin-top: 16px; }
.table th, .table td { padding: 10px 12px; border-bottom: 1px solid #1e293b; text-align: left; }
.tag { display: inline-block; background: #1e293b; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-size: 12px; margin-right: 4px; }
.badge { padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge.ok { background: #22c55e33; color: #4ade80; }
.badge.alert { background: #ef444433; color: #f87171; }
pre { white-space: pre-wrap; word-break: break-word; margin: 0; }
</style>
</head>
<body>
<header>
  <h1>RCE Guard Dashboard</h1>
  <button id=\"refresh\">Refresh</button>
</header>
<main>
  <p>The table below lists the most recent requests. Data refreshes automatically every two seconds.</p>
  <table class=\"table\">
    <thead>
      <tr>
        <th>Time</th>
        <th>Source</th>
        <th>Request</th>
        <th>Status</th>
        <th>Matches</th>
      </tr>
    </thead>
    <tbody id=\"events\"></tbody>
  </table>
</main>
<script>
async function fetchEvents() {
  const res = await fetch('/events?limit=50', { cache: 'no-store' });
  const payload = await res.json();
  return payload.events || [];
}
function formatTime(ts) {
  const date = new Date(ts * 1000);
  return date.toLocaleTimeString();
}
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
function render(events) {
  const tbody = document.getElementById('events');
  if (!tbody) return;
  tbody.innerHTML = events.map(event => {
    const badge = event.malicious ? '<span class="badge alert">Malicious</span>' : '<span class="badge ok">Benign</span>';
    const matchesText = event.matches.map(match => `${match.rule_id} (${match.severity})`);
    const matchesHtml = matchesText.length ? escapeHtml(matchesText.join(', ')) : '-';
    const tags = event.matches.flatMap(match => match.tags || []);
    const tagsHtml = [...new Set(tags)].map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('');
    const bodyPreview = escapeHtml(event.body_preview || '');
    const method = escapeHtml(event.method);
    const path = escapeHtml(event.path);
    const remote = escapeHtml(event.remote_addr || '-');
    const summary = escapeHtml(event.summary);
    return `<tr>
      <td>${formatTime(event.timestamp)}</td>
      <td>${remote}</td>
      <td><strong>${method}</strong> ${path}</td>
      <td>${badge}<div>${summary}</div></td>
      <td>${matchesHtml}<div>${tagsHtml}</div><pre>${bodyPreview}</pre></td>
    </tr>`;
  }).join('');
}
async function refresh() {
  const events = await fetchEvents();
  render(events);
}
document.getElementById('refresh').addEventListener('click', refresh);
setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>"""


class DetectionHandler(BaseHTTPRequestHandler):
    engine: RuleEngine | None = None
    event_log: EventLog | None = None
    notifier: Any | None = None

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, markup: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = markup.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record_event(self, request_payload: Dict[str, Any], response_payload: Dict[str, Any]) -> None:
        if not self.event_log:
            return
        event = {
            "timestamp": time.time(),
            "remote_addr": request_payload.get("remote_addr"),
            "method": request_payload.get("method"),
            "path": request_payload.get("path"),
            "query_string": request_payload.get("query_string"),
            "body_preview": request_payload.get("body_preview"),
            **response_payload,
        }
        self.event_log.add(event)

    def _summarize_request(self, request: HTTPRequest) -> Dict[str, Any]:
        query = request.query_string or ""
        body_preview = request.body if len(request.body) <= 160 else f"{request.body[:157]}..."
        return {
            "remote_addr": request.remote_addr,
            "method": request.method,
            "path": f"{request.path}{('?' + query) if query else ''}",
            "query_string": query,
            "body_preview": body_preview,
        }

    def do_GET(self) -> None:  # noqa: N802 (HTTP verb naming)
        parsed = urlparse(self.path)
        route = parsed.path
        if route == "/health":
            self._send_json({"status": "ok"})
        elif route in {"/", "/dashboard"}:
            self._send_html(DASHBOARD_HTML)
        elif route == "/events":
            limit_param = parse_qs(parsed.query).get("limit", [None])[0]
            limit = int(limit_param) if limit_param and limit_param.isdigit() else None
            events = self.event_log.snapshot(limit) if self.event_log else []
            self._send_json({"events": events})
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path
        if route not in {"/analyze", "/analyze/raw"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        try:
            if route == "/analyze":
                data = json.loads(body)
                request = dict_to_request(data)
            else:
                request = parse_raw_http(body, remote_addr=self.client_address[0])
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            return
        if request.remote_addr is None:
            request.remote_addr = self.client_address[0]
        result = self.engine.evaluate(request) if self.engine else None
        if result is None:
            self._send_json({"error": "Engine not configured"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        matches_payload = [
            {
                "rule_id": match.rule_id,
                "description": match.description,
                "severity": match.severity,
                "location": match.location,
                "tags": list(match.tags),
                "evidence": match.evidence,
            }
            for match in result.matches
        ]
        response = {
            "malicious": result.is_malicious,
            "summary": result.summary(),
            "matches": matches_payload,
            "request": {
                "method": request.method,
                "path": request.path,
                "query_string": request.query_string,
                "remote_addr": request.remote_addr,
            },
        }
        request_summary = self._summarize_request(request)
        self._record_event(request_summary, response)
        if result.is_malicious and getattr(self.notifier, "notify_detection", None):
            try:
                self.notifier.notify_detection(result)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to deliver notifier alert: %s", exc)
        self._send_json(response)

    def log_message(self, format: str, *args) -> None:  # noqa: A003 (shadow built-in)
        # Quiet default stdout logging to keep CLI clean; override if needed.
        return


def serve_http(engine: RuleEngine, host: str = "127.0.0.1", port: int = 8080, notifier: Any | None = None) -> None:
    event_log = EventLog()
    handler_cls = type(
        "BoundHandler",
        (DetectionHandler,),
        {"engine": engine, "event_log": event_log, "notifier": notifier},
    )
    server = ThreadingHTTPServer((host, port), handler_cls)
    print(f"[*] Serving detection API on http://{host}:{port}")
    print(f"[*] Dashboard available at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
