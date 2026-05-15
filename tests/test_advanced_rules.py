"""Tests for advanced security rules (GHA013-GHA015)."""

from pathlib import Path

import pytest

from ghactions_audit.rules import get_all_rules
from ghactions_audit.scanner import WorkflowScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def scanner():
    """Create a scanner with all rules enabled."""
    return WorkflowScanner(rules=get_all_rules())


@pytest.fixture
def advanced_vulnerable_file():
    return FIXTURES_DIR / "vulnerable_advanced.yml"


class TestGithubScriptInjection:
    """Tests for GHA013: actions/github-script injection."""

    def test_detects_script_injection(self, scanner, advanced_vulnerable_file):
        findings = scanner.scan_file(advanced_vulnerable_file)
        gha013 = [f for f in findings if f.rule_id == "GHA013"]
        assert len(gha013) >= 1
        assert any("pull_request.title" in f.description for f in gha013)

    def test_no_false_positive_without_dangerous_context(self, scanner, tmp_path):
        safe_workflow = tmp_path / "safe_script.yml"
        safe_workflow.write_text(
            """
name: Safe
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const result = await github.rest.repos.get({
              owner: context.repo.owner,
              repo: context.repo.repo,
            });
            console.log(result.data.name);
""",
            encoding="utf-8",
        )
        findings = scanner.scan_file(safe_workflow)
        gha013 = [f for f in findings if f.rule_id == "GHA013"]
        assert len(gha013) == 0


class TestWorkflowDispatchInjection:
    """Tests for GHA014: workflow_dispatch input injection."""

    def test_detects_dispatch_input_injection(self, scanner, advanced_vulnerable_file):
        findings = scanner.scan_file(advanced_vulnerable_file)
        gha014 = [f for f in findings if f.rule_id == "GHA014"]
        assert len(gha014) >= 2  # deploy_env and version
        assert any("deploy_env" in f.description for f in gha014)
        assert any("version" in f.description for f in gha014)

    def test_no_false_positive_on_push_trigger(self, scanner, tmp_path):
        no_dispatch = tmp_path / "push_only.yml"
        no_dispatch.write_text(
            """
name: Push Only
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Use variable
        run: echo "Hello ${{ github.sha }}"
""",
            encoding="utf-8",
        )
        findings = scanner.scan_file(no_dispatch)
        gha014 = [f for f in findings if f.rule_id == "GHA014"]
        assert len(gha014) == 0


class TestSecretExfiltrationRisk:
    """Tests for GHA015: secret exfiltration from untrusted triggers."""

    def test_detects_secret_in_untrusted_context(self, scanner, advanced_vulnerable_file):
        findings = scanner.scan_file(advanced_vulnerable_file)
        gha015 = [f for f in findings if f.rule_id == "GHA015"]
        assert len(gha015) >= 1
        assert any("NPM_TOKEN" in f.description or "DEPLOY_KEY" in f.description for f in gha015)

    def test_no_false_positive_on_push(self, scanner, tmp_path):
        safe = tmp_path / "safe_secrets.yml"
        safe.write_text(
            """
name: Safe
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Deploy
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: echo "Deploying"
""",
            encoding="utf-8",
        )
        findings = scanner.scan_file(safe)
        gha015 = [f for f in findings if f.rule_id == "GHA015"]
        assert len(gha015) == 0


class TestNewRulesIntegration:
    """Integration tests confirming new rules appear in get_all_rules."""

    def test_all_rules_includes_advanced(self):
        rules = get_all_rules()
        rule_ids = {r.rule_id for r in rules}
        assert "GHA013" in rule_ids
        assert "GHA014" in rule_ids
        assert "GHA015" in rule_ids

    def test_rule_count_increased(self):
        rules = get_all_rules()
        assert len(rules) >= 15  # 12 original + 3 new
