# RCE Guard Architecture

## Request Flow

1. A user (or attacker) sends an HTTP request to the demo application or the request is ingested from logs.
2. The request is normalized into an `HTTPRequest` instance (via JSON/raw parsers or CLI input).
3. The `RuleEngine` iterates through each `Rule`, applying the compiled regex against the configured fields (`body`, `query_string`, `headers`, etc.).
4. When a regex matches, the engine emits a `RuleMatch` containing evidence that can be logged or alerted on.
5. A `DetectionResult` aggregates all matches and exposes the overall malicious/benign verdict with the highest severity level.

## Key Modules

- `models.py`: Defines `HTTPRequest`, `RuleMatch`, and `DetectionResult`, including severity ranking helpers.
- `rules.py`: Declares the `Rule` data type, the default `DEFAULT_RULES`, and utilities to load rules from JSON.
- `engine.py`: Houses `RuleEngine`, which accepts configuration, evaluates requests, and returns results.
- `parsers.py`: Converts JSON or raw HTTP payloads into `HTTPRequest` objects.
- `server.py`: Implements the HTTP API demo (`/analyze`, `/analyze/raw`, `/health`) plus the realtime dashboard (`/`, `/events`).
- `notifiers.py`: Notification layer (currently Telegram) with built-in demo credentials.
- `cli.py`: Unified CLI for scanning requests, scanning logs, running the API server, and managing notifiers.

## Default Rule Coverage

The bundled rules target common RCE techniques:

- Unix shell command chaining (`;`, `&&`, `bash`, `nc`, etc.).
- Java `Runtime.getRuntime().exec` invocation attempts.
- PHP execution helpers such as `system`, `exec`, `shell_exec`, etc.
- Python `eval`/`exec` usage and `os.system` calls.
- Template sandbox escapes (e.g., Jinja2 `__mro__` traversal).
- Reverse shell patterns like `/dev/tcp/x.x.x.x/port`.
- PowerShell `-EncodedCommand` execution.
- Log4Shell-style `${jndi:...}` payloads.

## Extensibility

- Load custom JSON rule sets (optionally disabling the defaults).
- Embed the `RuleEngine` into real WAF/IDS pipelines as middleware or plugins.
- Stream `DetectionResult` objects into SIEM/EDR systems for correlation and alerting.
