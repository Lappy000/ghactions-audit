"""Configuration loader for ghactions-audit.

Supports .ghactions-audit.yml in the project root for per-repo
rule customization, severity overrides, and ignore patterns.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import yaml


@dataclass
class RuleConfig:
    """Configuration override for a specific rule."""
    enabled: bool = True
    severity: Optional[str] = None  # Override default severity


@dataclass
class Config:
    """Audit configuration loaded from .ghactions-audit.yml."""
    ignore_rules: Set[str] = field(default_factory=set)
    ignore_paths: List[str] = field(default_factory=list)
    min_severity: str = "low"
    rule_overrides: Dict[str, RuleConfig] = field(default_factory=dict)
    trusted_orgs: Set[str] = field(default_factory=set)
    allow_unpinned: Set[str] = field(default_factory=set)  # Actions allowed to use tags

    @classmethod
    def load(cls, directory: Path) -> "Config":
        """Load config from .ghactions-audit.yml in directory, or return defaults."""
        config_names = [".ghactions-audit.yml", ".ghactions-audit.yaml"]
        for name in config_names:
            config_path = directory / name
            if config_path.exists():
                return cls._parse(config_path)
        return cls()

    @classmethod
    def _parse(cls, path: Path) -> "Config":
        """Parse config file into Config instance."""
        try:
            content = path.read_text(encoding="utf-8")
            data = yaml.safe_load(content) or {}
        except (OSError, yaml.YAMLError):
            return cls()

        if not isinstance(data, dict):
            return cls()

        config = cls()

        # ignore_rules: list of rule IDs to skip
        if "ignore" in data and isinstance(data["ignore"], list):
            config.ignore_rules = set(data["ignore"])

        # ignore_paths: glob patterns for files to skip
        if "ignore_paths" in data and isinstance(data["ignore_paths"], list):
            config.ignore_paths = data["ignore_paths"]

        # min_severity
        if "severity" in data and data["severity"] in ("low", "medium", "high", "critical"):
            config.min_severity = data["severity"]

        # trusted_orgs: additional orgs to treat as trusted for GHA006
        if "trusted_orgs" in data and isinstance(data["trusted_orgs"], list):
            config.trusted_orgs = set(data["trusted_orgs"])

        # allow_unpinned: actions that are OK to reference by tag
        if "allow_unpinned" in data and isinstance(data["allow_unpinned"], list):
            config.allow_unpinned = set(data["allow_unpinned"])

        # rules: per-rule overrides
        if "rules" in data and isinstance(data["rules"], dict):
            for rule_id, rule_data in data["rules"].items():
                if not isinstance(rule_data, dict):
                    continue
                config.rule_overrides[rule_id] = RuleConfig(
                    enabled=rule_data.get("enabled", True),
                    severity=rule_data.get("severity"),
                )

        return config

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled considering all config sources."""
        if rule_id in self.ignore_rules:
            return False
        override = self.rule_overrides.get(rule_id)
        if override and not override.enabled:
            return False
        return True

    def get_severity_override(self, rule_id: str) -> Optional[str]:
        """Get severity override for a rule, if configured."""
        override = self.rule_overrides.get(rule_id)
        if override and override.severity:
            return override.severity
        return None
