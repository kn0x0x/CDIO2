from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(slots=True)
class HTTPRequest:
    """Represents an incoming HTTP request to be inspected."""

    method: str
    path: str
    query_string: str | None
    headers: Dict[str, str]
    body: str
    remote_addr: str | None = None
    protocol: str = "HTTP/1.1"

    def materialized_fields(self) -> Dict[str, str]:
        """Return a mapping of logical locations to string data for rule matching."""
        header_blob = "\n".join(f"{k.lower()}: {v}" for k, v in self.headers.items())
        return {
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string or "",
            "headers": header_blob,
            "body": self.body or "",
            "full_request": f"{self.method} {self.path}{('?' + self.query_string) if self.query_string else ''}\n{header_blob}\n\n{self.body}",
        }


@dataclass(slots=True)
class RuleMatch:
    """Details about a specific rule match."""

    rule_id: str
    description: str
    severity: str
    evidence: str
    location: str
    tags: Tuple[str, ...] = field(default_factory=tuple)
    span: Optional[Tuple[int, int]] = None


@dataclass(slots=True)
class DetectionResult:
    """Result of evaluating a request against the rule engine."""

    request: HTTPRequest
    matches: List[RuleMatch]

    @property
    def is_malicious(self) -> bool:
        return bool(self.matches)

    def summary(self) -> str:
        if not self.matches:
            return "benign"
        worst = max(self.matches, key=lambda m: SEVERITY_ORDER.get(m.severity.upper(), 0))
        return f"malicious:{worst.severity.lower()}"


# Severity ranking for quick comparison
SEVERITY_ORDER = {
    "INFO": 10,
    "LOW": 20,
    "MEDIUM": 30,
    "HIGH": 40,
    "CRITICAL": 50,
}
