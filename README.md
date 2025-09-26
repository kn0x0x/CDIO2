# RCE Guard

RCE Guard is a compact rule-based engine that mimics a WAF/IDS pipeline for detecting Remote Code Execution (RCE) payloads. The project ships with a Python rule engine, a command-line interface for scanning individual requests or log files, and a lightweight HTTP API with a realtime dashboard.

## Project Layout

- `src/rce_guard`: Core rule engine, default rule set, request parsers, notifier integration, and demo HTTP server.
- `tests/`: Unit tests built with the Python standard library `unittest` runner.
- `samples/requests.jsonl`: Example JSONL log you can scan to see detections in action.

## Requirements

- Python 3.10 or newer (no third-party dependencies required for core features).

## Installation & Test Execution

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python3 -m unittest discover -s tests
```

> Installing in editable mode makes the `rce-guard` CLI instantly available inside the virtual environment.
## CLI Usage

Scan a single request described on the command line:

```bash
rce-guard scan-request --method POST --path /upload \
  --body "file=data&cmd=system('id')" \
  --header "Content-Type: application/x-www-form-urlencoded"
```

Scan an existing JSON Lines log:

```bash
rce-guard scan-log samples/requests.jsonl --summary
```

Load a custom JSON rule set (optionally replacing the defaults):

```bash
rce-guard --rules custom_rules.json --disable-defaults scan-request --json request.json
```
## Telegram Notifications

Telegram alerts are enabled out of the box using the bundled demo bot token (`8129718611:...`) and chat ID (`6325753293`). Simply run any scan and the notifier will push a message when a payload is flagged.

```bash
# Scan a sample log and emit Telegram alerts for malicious entries
rce-guard scan-log samples/requests.jsonl --summary
```

Provide your own credentials via environment variables or CLI flags if preferred:

```bash
export RCE_GUARD_TELEGRAM_TOKEN="your_token"
export RCE_GUARD_TELEGRAM_CHAT_ID="your_chat_id"
# or use --telegram-token / --telegram-chat-id
```

If you operate behind an intercepting proxy with a self-signed certificate, you can instruct the notifier to skip TLS validation (only in trusted environments):

```bash
export RCE_GUARD_TELEGRAM_INSECURE=1
```

Add `--disable-telegram` to any command to suppress alerts temporarily.
## HTTP API Demo

```bash
rce-guard serve --host 0.0.0.0 --port 8080
```

- Visit `http://0.0.0.0:8080/` for the realtime dashboard (refreshes every 2 seconds).
- `POST /analyze`: Submit a JSON request document (same format as the CLI accepts).
- `POST /analyze/raw`: Submit a raw HTTP request payload.
- `GET /health`: Health probe endpoint.
- `GET /events`: Fetch the most recent events as JSON (supports `limit` query parameter).

## Rule Structure

Rules are expressed as regex definitions plus metadata, for example:

```json
{
  "id": "RCE-999",
  "description": "Example description",
  "severity": "HIGH",
  "pattern": "regex",
  "fields": ["body", "headers"],
  "tags": ["python"]
}
```

Multiple rules can be declared in one JSON file and loaded into the engine.

## Potential Enhancements

- Add statistics for false positive/false negative tracking.
- Build a rule management UI with enable/disable toggles.
- Integrate additional rule sources (Sigma, threat intelligence feeds, etc.).
