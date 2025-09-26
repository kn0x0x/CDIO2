from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Pattern, Sequence, Tuple

from .models import HTTPRequest, RuleMatch


@dataclass(slots=True)
class Rule:
    """Single detection rule expressed as a regular expression pattern."""

    rule_id: str
    description: str
    severity: str
    pattern: str
    fields: Tuple[str, ...] = ("full_request",)
    tags: Tuple[str, ...] = ()
    case_insensitive: bool = True
    compiled: Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE if self.case_insensitive else 0
        self.compiled = re.compile(self.pattern, flags)

    def finditer(self, request: HTTPRequest) -> Iterable[RuleMatch]:
        materials = request.materialized_fields()
        for field in self.fields:
            haystack = materials.get(field, "")
            for match in self.compiled.finditer(haystack):
                snippet = _extract_snippet(haystack, match.start(), match.end())
                yield RuleMatch(
                    rule_id=self.rule_id,
                    description=self.description,
                    severity=self.severity,
                    evidence=snippet,
                    location=field,
                    tags=self.tags,
                    span=(match.start(), match.end()),
                )

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        return cls(
            rule_id=data["id"],
            description=data.get("description", data["id"]),
            severity=data.get("severity", "MEDIUM"),
            pattern=data["pattern"],
            fields=tuple(data.get("fields", ["full_request"])),
            tags=tuple(data.get("tags", [])),
            case_insensitive=data.get("case_insensitive", True),
        )


def _extract_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    pre = max(start - radius, 0)
    post = min(end + radius, len(text))
    snippet = text[pre:start] + "➡" + text[start:end] + "⬅" + text[end:post]
    return snippet.replace("\n", " ")


def load_rules_from_json(path: Path) -> List[Rule]:
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("Rules JSON must be a list of rule definitions")
    return [Rule.from_dict(item) for item in data]


DEFAULT_RULES: Tuple[Rule, ...] = (
    Rule(
        rule_id="RCE-001",
        description="UNIX command injection with shell metacharacters",
        severity="HIGH",
        pattern=r"(;|&&|\|\|)\s*(?:cat|sh|bash|nc|python|perl|php|ruby)\b",
        fields=("query_string", "body"),
        tags=("command-injection", "unix"),
    ),
    Rule(
        rule_id="RCE-002",
        description="Attempt to invoke Runtime.exec in Java",
        severity="HIGH",
        pattern=r"Runtime\.getRuntime\(\)\.exec",
        fields=("body",),
        tags=("java", "runtime-exec"),
    ),
    Rule(
        rule_id="RCE-003",
        description="PHP code execution helper functions",
        severity="HIGH",
        pattern=r"\b(?:system|shell_exec|passthru|exec|pcntl_exec|popen)\s*\(",
        fields=("body", "query_string"),
        tags=("php", "command-injection"),
    ),
    Rule(
        rule_id="RCE-004",
        description="Python eval or os.system execution",
        severity="HIGH",
        pattern=r"\b(?:eval|exec|compile)\s*\(|os\.system\(",
        fields=("body", "query_string"),
        tags=("python", "eval"),
    ),
    Rule(
        rule_id="RCE-005",
        description="Template injection sandbox breakout (Jinja2 style)",
        severity="CRITICAL",
        pattern=r"__mro__\[1\].__subclasses__\(\)",
        fields=("body",),
        tags=("template-injection",),
    ),
    Rule(
        rule_id="RCE-006",
        description="Attempt to spawn reverse shell",
        severity="CRITICAL",
        pattern=r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+",
        fields=("body", "query_string"),
        tags=("reverse-shell",),
    ),
    Rule(
        rule_id="RCE-007",
        description="PowerShell encoded command execution",
        severity="HIGH",
        pattern=r"powershell\.exe\s*-EncodedCommand\s+[A-Za-z0-9+/=]{20,}",
        fields=("body", "headers"),
        tags=("windows", "powershell"),
    ),
    Rule(
        rule_id="RCE-008",
        description="Log4Shell style JNDI lookup",
        severity="CRITICAL",
        pattern=r"\$\{jndi:[^}]+\}",
        fields=("headers", "body"),
        tags=("log4shell", "jndi"),
    ),
)
