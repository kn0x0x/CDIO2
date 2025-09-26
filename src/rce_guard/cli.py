from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, List

from .engine import RuleEngine, RuleEngineConfig
from .models import DetectionResult, HTTPRequest
from .notifiers import DummyNotifier, TelegramNotifier
from .parsers import dict_to_request, json_line_to_request, parse_raw_http
from .server import serve_http


def parse_kv_pairs(values: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in values:
        if ":" not in item:
            raise ValueError(f"Header must be in key:value format, got: {item}")
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def build_engine(args: argparse.Namespace) -> RuleEngine:
    rules_path = Path(args.rules) if args.rules else None
    config = RuleEngineConfig(rules_path=rules_path, include_default_rules=not args.disable_defaults)
    return RuleEngine(config=config)


def build_notifier(args: argparse.Namespace) -> TelegramNotifier | DummyNotifier:
    if getattr(args, "disable_telegram", False):
        return DummyNotifier()
    token = getattr(args, "telegram_token", None)
    chat_id = getattr(args, "telegram_chat_id", None)
    notifier = TelegramNotifier.from_args(token, chat_id)
    return notifier if notifier.enabled else DummyNotifier()



def detection_to_dict(result: DetectionResult) -> dict[str, object]:
    return {
        "malicious": result.is_malicious,
        "summary": result.summary(),
        "matches": [
            {
                "rule_id": match.rule_id,
                "description": match.description,
                "severity": match.severity,
                "tags": list(match.tags),
                "location": match.location,
                "evidence": match.evidence,
            }
            for match in result.matches
        ],
    }



def handle_scan_request(args: argparse.Namespace) -> int:
    engine = build_engine(args)
    notifier = build_notifier(args)
    if args.raw:
        request = parse_raw_http(Path(args.raw).read_text())
    elif args.json:
        data = json.loads(Path(args.json).read_text())
        if isinstance(data, list):
            results = [engine.evaluate(dict_to_request(item)) for item in data]
            payload = [detection_to_dict(result) for result in results]
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            for result in results:
                if result.is_malicious:
                    notifier.notify_detection(result)
            return any(result.is_malicious for result in results)
        request = dict_to_request(data)
    else:
        headers = parse_kv_pairs(args.header or [])
        request = HTTPRequest(
            method=args.method,
            path=args.path,
            query_string=args.query,
            headers=headers,
            body=args.body or "",
            remote_addr=args.remote_addr,
            protocol="HTTP/1.1",
        )
    result = engine.evaluate(request)
    if result.is_malicious:
        notifier.notify_detection(result)
    print(json.dumps(detection_to_dict(result), indent=2, ensure_ascii=False))
    return int(result.is_malicious)


def handle_scan_log(args: argparse.Namespace) -> int:
    engine = build_engine(args)
    notifier = build_notifier(args)
    path = Path(args.path)
    total = 0
    flagged = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        total += 1
        request = json_line_to_request(line)
        result = engine.evaluate(request)
        if result.is_malicious:
            flagged += 1
            notifier.notify_detection(result)
            print(json.dumps({"line": total, **detection_to_dict(result)}, ensure_ascii=False))
    if args.summary:
        summary = {"processed": total, "flagged": flagged, "ratio": (flagged / total) if total else 0.0}
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    return int(flagged > 0)


def handle_serve(args: argparse.Namespace) -> int:
    engine = build_engine(args)
    notifier = build_notifier(args)
    serve_http(engine, host=args.host, port=args.port, notifier=notifier)
    return 0



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Rule-based RCE payload detector")
    parser.add_argument("--rules", help="Path to JSON rule set to load in addition to defaults")
    parser.add_argument("--disable-defaults", action="store_true", help="Use only user-supplied rules")
    parser.add_argument("--telegram-token", help="Telegram bot token (fallback to env RCE_GUARD_TELEGRAM_TOKEN)")
    parser.add_argument("--telegram-chat-id", help="Telegram chat id (fallback to env RCE_GUARD_TELEGRAM_CHAT_ID)")
    parser.add_argument("--disable-telegram", action="store_true", help="Disable Telegram notifications")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_request = sub.add_parser("scan-request", help="Inspect a single request")
    scan_request.add_argument("--method", default="GET")
    scan_request.add_argument("--path", default="/")
    scan_request.add_argument("--query", help="Raw query string")
    scan_request.add_argument("--body", help="Request body")
    scan_request.add_argument("--header", action="append", help="Header key:value pairs", dest="header")
    scan_request.add_argument("--remote-addr", help="Remote IP address")
    scan_request.add_argument("--json", help="Path to JSON file describing the request")
    scan_request.add_argument("--raw", help="Path to raw HTTP request text")
    scan_request.set_defaults(func=handle_scan_request)

    scan_log = sub.add_parser("scan-log", help="Scan JSONL log file")
    scan_log.add_argument("path", help="Path to JSON lines log")
    scan_log.add_argument("--summary", action="store_true", help="Print summary statistics")
    scan_log.set_defaults(func=handle_scan_log)

    serve = sub.add_parser("serve", help="Run minimal HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.set_defaults(func=handle_serve)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        parser.error(str(exc))
    except FileNotFoundError as exc:
        parser.error(f"{exc}")
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
