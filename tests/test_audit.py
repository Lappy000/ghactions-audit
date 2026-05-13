"""Test suite for ghactions-audit."""

import json
from pathlib import Path

import pytest

from ghactions_audit.scanner import WorkflowScanner, Finding
from ghactions_audit.rules import get_all_rules
from ghactions_audit.config import Config
from ghactions_audit.sarif import render_sarif

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def scanner():
    """Create a scanner with all rules enabled."""
    return WorkflowScanner(rules=get_all_rules())


@pytest.fixture
def vulnerable_file():
    return FIXTURES_DIR / "vulnerable.yml"


@pytest.fixture
def secure_file():
    return FIXTURES_DIR / "secure.yml"


class TestVulnerableWorkflow:
    """Tests against the deliberately vulnerable workflow fixture."""

    def test_finds_issues(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        assert len(findings) > 0

    def test_detects_unpinned_actions(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        unpinned = [f for f in findings if f.rule_id == "GHA001"]
        assert len(unpinned) >= 3  # checkout@v4, setup-node@v4, install-action@main

    def test_detects_dangerous_trigger(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        triggers = [f for f in findings if f.rule_id == "GHA002"]
        assert len(triggers) >= 1
        assert any("pull_request_target" in f.description for f in triggers)

    def test_detects_write_all(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        perms = [f for f in findings if f.rule_id == "GHA003"]
        assert any("write-all" in f.description for f in perms)

    def test_detects_script_injection(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        injection = [f for f in findings if f.rule_id == "GHA004"]
        assert len(injection) >= 1
        assert any("pull_request.title" in f.description for f in injection)

    def test_detects_secret_in_logs(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        secrets = [f for f in findings if f.rule_id == "GHA005"]
        assert len(secrets) >= 1

    def test_detects_third_party(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        third_party = [f for f in findings if f.rule_id == "GHA006"]
        assert any("some-random-org" in f.description for f in third_party)

    def test_detects_self_hosted(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        runner = [f for f in findings if f.rule_id == "GHA007"]
        assert len(runner) >= 1
        # Should be critical because PR trigger + self-hosted
        assert any(f.severity == "critical" for f in runner)

    def test_detects_env_injection(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        env_inj = [f for f in findings if f.rule_id == "GHA010"]
        assert len(env_inj) >= 1

    def test_detects_artifact_issue(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        artifacts = [f for f in findings if f.rule_id == "GHA009"]
        assert len(artifacts) >= 1

    def test_detects_oidc_issue(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        oidc = [f for f in findings if f.rule_id == "GHA012"]
        assert len(oidc) >= 1

    def test_detects_cache_issue(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        cache = [f for f in findings if f.rule_id == "GHA011"]
        assert len(cache) >= 1


class TestSecureWorkflow:
    """Tests against the secure workflow fixture — should have minimal findings."""

    def test_minimal_findings(self, scanner, secure_file):
        findings = scanner.scan_file(secure_file)
        # Secure workflow should have no high/critical findings
        serious = [f for f in findings if f.severity in ("high", "critical")]
        assert len(serious) == 0

    def test_no_unpinned_actions(self, scanner, secure_file):
        findings = scanner.scan_file(secure_file)
        unpinned = [f for f in findings if f.rule_id == "GHA001"]
        assert len(unpinned) == 0


class TestConfig:
    """Test configuration loading and application."""

    def test_default_config(self):
        config = Config()
        assert config.min_severity == "low"
        assert len(config.ignore_rules) == 0

    def test_rule_enable_check(self):
        config = Config()
        config.ignore_rules = {"GHA001", "GHA002"}
        assert not config.is_rule_enabled("GHA001")
        assert not config.is_rule_enabled("GHA002")
        assert config.is_rule_enabled("GHA003")

    def test_severity_override(self):
        from ghactions_audit.config import RuleConfig
        config = Config()
        config.rule_overrides = {"GHA006": RuleConfig(severity="high")}
        assert config.get_severity_override("GHA006") == "high"
        assert config.get_severity_override("GHA001") is None


class TestSarif:
    """Test SARIF output generation."""

    def test_sarif_structure(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        sarif_output = render_sarif(findings)
        sarif = json.loads(sarif_output)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "ghactions-audit"
        assert len(sarif["runs"][0]["results"]) > 0

    def test_sarif_rules_populated(self, scanner, vulnerable_file):
        findings = scanner.scan_file(vulnerable_file)
        sarif_output = render_sarif(findings)
        sarif = json.loads(sarif_output)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0
        assert all("id" in r for r in rules)

    def test_empty_findings_sarif(self):
        sarif_output = render_sarif([])
        sarif = json.loads(sarif_output)
        assert sarif["runs"][0]["results"] == []


class TestScanner:
    """Test scanner edge cases."""

    def test_nonexistent_file(self, scanner, tmp_path):
        fake_file = tmp_path / "nonexistent.yml"
        fake_file.write_text("not: valid: yaml: {{{}}", encoding="utf-8")
        findings = scanner.scan_file(fake_file)
        assert any(f.rule_id == "PARSE002" for f in findings)

    def test_empty_yaml(self, scanner, tmp_path):
        empty_file = tmp_path / "empty.yml"
        empty_file.write_text("", encoding="utf-8")
        findings = scanner.scan_file(empty_file)
        assert len(findings) == 0

    def test_ignore_rules(self, vulnerable_file):
        scanner = WorkflowScanner(
            rules=get_all_rules(),
            ignore_rules={"GHA001", "GHA002", "GHA003", "GHA004", "GHA005",
                          "GHA006", "GHA007", "GHA008", "GHA009", "GHA010",
                          "GHA011", "GHA012"}
        )
        findings = scanner.scan_file(vulnerable_file)
        assert len(findings) == 0
