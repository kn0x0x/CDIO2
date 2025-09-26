from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .models import DetectionResult, HTTPRequest, RuleMatch
from .rules import DEFAULT_RULES, Rule, load_rules_from_json


@dataclass(slots=True)
class RuleEngineConfig:
    """Configuration object allowing customization of the engine."""

    rules_path: Path | None = None
    include_default_rules: bool = True


class RuleEngine:
    """Evaluate HTTP requests against a set of RCE detection rules."""

    def __init__(self, rules: Sequence[Rule] | None = None, *, config: RuleEngineConfig | None = None) -> None:
        self._config = config or RuleEngineConfig()
        custom_rules = list(rules or [])
        if self._config.rules_path:
            custom_rules.extend(load_rules_from_json(self._config.rules_path))
        if self._config.include_default_rules:
            custom_rules = list(DEFAULT_RULES) + custom_rules
        if not custom_rules:
            raise ValueError("Rule engine requires at least one rule")
        self.rules: tuple[Rule, ...] = tuple(custom_rules)

    def evaluate(self, request: HTTPRequest) -> DetectionResult:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            matches.extend(rule.finditer(request))
        return DetectionResult(request=request, matches=matches)

    def iter_matches(self, request: HTTPRequest) -> Iterable[RuleMatch]:
        for rule in self.rules:
            yield from rule.finditer(request)

    @classmethod
    def from_json_rules(cls, path: Path, *, include_defaults: bool = True) -> "RuleEngine":
        rules = load_rules_from_json(path)
        config = RuleEngineConfig(include_default_rules=include_defaults)
        return cls(rules=rules, config=config)
