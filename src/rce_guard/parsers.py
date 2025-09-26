from __future__ import annotations

import json
from typing import Any, Dict, Iterable

from .models import HTTPRequest


def dict_to_request(payload: Dict[str, Any]) -> HTTPRequest:
    headers = {k: str(v) for k, v in payload.get("headers", {}).items()}
    return HTTPRequest(
        method=payload.get("method", "GET").upper(),
        path=payload.get("path", "/"),
        query_string=payload.get("query_string"),
        headers=headers,
        body=payload.get("body", ""),
        remote_addr=payload.get("remote_addr"),
        protocol=payload.get("protocol", "HTTP/1.1"),
    )


def json_line_to_request(line: str) -> HTTPRequest:
    data = json.loads(line)
    if not isinstance(data, dict):
        raise ValueError("Each JSON line must describe an HTTP request object")
    return dict_to_request(data)


def parse_raw_http(raw: str, *, remote_addr: str | None = None) -> HTTPRequest:
    head, _, body = raw.partition("\r\n\r\n")
    if not body:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("Invalid raw HTTP request: missing request line")
    request_line = lines[0]
    parts = request_line.split()
    if len(parts) < 2:
        raise ValueError("Invalid request line")
    method = parts[0]
    path = parts[1]
    protocol = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
    query_string = None
    if "?" in path:
        path, query_string = path.split("?", 1)
    return HTTPRequest(
        method=method,
        path=path,
        query_string=query_string,
        headers=headers,
        body=body,
        remote_addr=remote_addr,
        protocol=protocol,
    )
