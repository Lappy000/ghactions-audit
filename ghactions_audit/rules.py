"""Security rules for GitHub Actions workflow auditing."""

import re
from abc import ABC, abstractmethod
from typing import List

from .scanner import Finding


class Rule(ABC):
    """Base class for all audit rules."""

    rule_id: str = ""
    title: str = ""
    severity: str = "medium"

    @abstractmethod
    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        """Check a parsed workflow against this rule. Return findings."""
        ...

    def _find_line(self, lines: list, pattern: str, start: int = 0) -> int:
        """Find the first line number matching a regex pattern."""
        for i, line in enumerate(lines[start:], start=start + 1):
            if re.search(pattern, line):
                return i
        return 0


class UnpinnedActionsRule(Rule):
    """Detects actions referenced by tag/branch instead of full SHA."""

    rule_id = "GHA001"
    title = "Unpinned action reference"
    severity = "high"

    # Pattern for uses: org/repo@ref where ref is NOT a 40-char hex SHA
    SHA_RE = re.compile(r"^[a-f0-9]{40}$")

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", []) or []
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if not uses or "/" not in uses:
                    continue
                # Skip local actions (./path)
                if uses.startswith("./"):
                    continue
                # Check if pinned to SHA
                if "@" in uses:
                    ref = uses.split("@", 1)[1]
                    if self.SHA_RE.match(ref):
                        continue
                    line = self._find_line(lines, re.escape(uses))
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        file=filepath,
                        line=line,
                        title=self.title,
                        description=f"Action '{uses}' is pinned to a mutable tag/branch, not a commit SHA.",
                        remediation=f"Pin to a full commit SHA: {uses.split('@')[0]}@<commit-sha>"
                    ))
                else:
                    line = self._find_line(lines, re.escape(uses))
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity="critical",
                        file=filepath,
                        line=line,
                        title="Action without version reference",
                        description=f"Action '{uses}' has no version pin at all.",
                        remediation=f"Add a SHA pin: {uses}@<commit-sha>"
                    ))
        return findings


class DangerousTriggerRule(Rule):
    """Detects use of pull_request_target and workflow_run without safeguards."""

    rule_id = "GHA002"
    title = "Dangerous workflow trigger"
    severity = "critical"

    DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        triggers = workflow.get("on", workflow.get(True, {}))

        if isinstance(triggers, str):
            triggers = {triggers: None}
        elif isinstance(triggers, list):
            triggers = {t: None for t in triggers}
        elif not isinstance(triggers, dict):
            return []

        for trigger_name in triggers:
            if trigger_name in self.DANGEROUS_TRIGGERS:
                line = self._find_line(lines, rf"^\s*{trigger_name}\s*:")
                # Check if the workflow also checks out PR code (extremely dangerous combo)
                checkout_found = self._has_pr_checkout(workflow)
                sev = "critical" if checkout_found else "high"
                desc = f"Trigger '{trigger_name}' runs with write permissions on the base repo."
                if checkout_found:
                    desc += " Combined with a checkout of PR code, this enables arbitrary code execution."
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=sev,
                    file=filepath,
                    line=line,
                    title=self.title,
                    description=desc,
                    remediation=f"Avoid '{trigger_name}' or ensure it never checks out/executes untrusted PR code."
                ))
        return findings

    def _has_pr_checkout(self, workflow: dict) -> bool:
        """Check if any job step checks out PR code."""
        jobs = workflow.get("jobs", {}) or {}
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in (job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if "actions/checkout" in uses:
                    with_block = step.get("with", {}) or {}
                    ref = with_block.get("ref", "")
                    if "pull_request" in str(ref).lower() or "head" in str(ref).lower():
                        return True
        return False


class OverlyPermissivePermissionsRule(Rule):
    """Detects workflows with write-all or overly broad permissions."""

    rule_id = "GHA003"
    title = "Overly permissive permissions"
    severity = "high"

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []

        # Check top-level permissions
        perms = workflow.get("permissions")
        if perms is None:
            # No permissions block = default token permissions (potentially broad)
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="medium",
                file=filepath,
                line=0,
                title="Missing permissions block",
                description="Workflow has no top-level permissions block. The GITHUB_TOKEN gets default (potentially broad) permissions.",
                remediation="Add a top-level 'permissions: {}' block and grant only what's needed per job."
            ))
        elif perms == "write-all":
            line = self._find_line(lines, r"permissions:\s*write-all")
            findings.append(Finding(
                rule_id=self.rule_id,
                severity="critical",
                file=filepath,
                line=line,
                title=self.title,
                description="Workflow grants write-all permissions to the GITHUB_TOKEN.",
                remediation="Use least-privilege: specify only the permissions each job needs."
            ))

        # Check per-job permissions
        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if job_perms == "write-all":
                line = self._find_line(lines, r"permissions:\s*write-all")
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity="critical",
                    file=filepath,
                    line=line,
                    title=f"Job '{job_name}' has write-all permissions",
                    description=f"Job '{job_name}' grants write-all to the GITHUB_TOKEN.",
                    remediation="Restrict to needed permissions only."
                ))

        return findings


class ScriptInjectionRule(Rule):
    """Detects potential script injection via untrusted context expressions."""

    rule_id = "GHA004"
    title = "Potential script injection"
    severity = "critical"

    # Expressions that can be attacker-controlled
    DANGEROUS_CONTEXTS = [
        r"github\.event\.issue\.title",
        r"github\.event\.issue\.body",
        r"github\.event\.pull_request\.title",
        r"github\.event\.pull_request\.body",
        r"github\.event\.comment\.body",
        r"github\.event\.review\.body",
        r"github\.event\.discussion\.title",
        r"github\.event\.discussion\.body",
        r"github\.event\.pages\.\*\.page_name",
        r"github\.event\.commits\.\*\.message",
        r"github\.event\.commits\.\*\.author\.name",
        r"github\.event\.head_commit\.message",
        r"github\.event\.head_commit\.author\.name",
        r"github\.event\.head_commit\.author\.email",
        r"github\.head_ref",
        r"github\.event\.workflow_run\.head_branch",
        r"github\.event\.workflow_run\.head_commit\.message",
    ]

    INJECTION_PATTERN = re.compile(
        r"\$\{\{\s*(" + "|".join(DANGEROUS_CONTEXTS) + r")\s*\}\}"
    )

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", []) or []
            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                run_cmd = step.get("run", "")
                if not run_cmd:
                    continue

                for match in self.INJECTION_PATTERN.finditer(run_cmd):
                    expr = match.group(1)
                    line = self._find_line(lines, re.escape(match.group(0)))
                    step_name = step.get("name", f"step {step_idx}")
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        file=filepath,
                        line=line,
                        title=self.title,
                        description=f"Expression '${{{{ {expr} }}}}' in job '{job_name}', {step_name} can be attacker-controlled. If interpolated into a shell command, this enables arbitrary code execution.",
                        remediation="Use an intermediate environment variable: env: TITLE: ${{ ... }} and reference $TITLE in the script."
                    ))
        return findings


class SecretsInLogsRule(Rule):
    """Detects potential secret leakage in run commands."""

    rule_id = "GHA005"
    title = "Potential secret exposure in logs"
    severity = "high"

    ECHO_SECRET_RE = re.compile(
        r"echo\s+.*\$\{\{\s*secrets\.[^}]+\}\}", re.IGNORECASE
    )
    PRINT_SECRET_RE = re.compile(
        r"(print|printf|cat)\s+.*\$\{\{\s*secrets\.[^}]+\}\}", re.IGNORECASE
    )

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for step in (job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                run_cmd = step.get("run", "")
                if not run_cmd:
                    continue
                for pattern in (self.ECHO_SECRET_RE, self.PRINT_SECRET_RE):
                    for match in pattern.finditer(run_cmd):
                        line = self._find_line(lines, re.escape(match.group(0)[:40]))
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            file=filepath,
                            line=line,
                            title=self.title,
                            description=f"Secret value may be printed to logs in job '{job_name}'. GitHub masks known secrets, but partial or transformed values can leak.",
                            remediation="Never echo secrets directly. Use them only as environment variables passed to tools."
                        ))
        return findings


class ThirdPartyActionRule(Rule):
    """Flags usage of actions from non-verified publishers."""

    rule_id = "GHA006"
    title = "Third-party action usage"
    severity = "low"

    TRUSTED_ORGS = {
        "actions", "github", "docker", "azure", "aws-actions",
        "google-github-actions", "hashicorp", "codecov",
    }

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for step in (job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if not uses or uses.startswith("./"):
                    continue
                org = uses.split("/")[0]
                if org not in self.TRUSTED_ORGS:
                    line = self._find_line(lines, re.escape(uses))
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        file=filepath,
                        line=line,
                        title=self.title,
                        description=f"Action '{uses}' is from non-verified org '{org}'. Review the action source before use.",
                        remediation=f"Audit {uses.split('@')[0]} source code or fork it into your org."
                    ))
        return findings


class SelfHostedRunnerRule(Rule):
    """Detects self-hosted runners used with public repo triggers."""

    rule_id = "GHA007"
    title = "Self-hosted runner usage"
    severity = "high"

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        triggers = workflow.get("on", workflow.get(True, {}))
        has_pr_trigger = False

        if isinstance(triggers, str):
            has_pr_trigger = triggers in ("pull_request", "pull_request_target")
        elif isinstance(triggers, list):
            has_pr_trigger = any(t in ("pull_request", "pull_request_target") for t in triggers)
        elif isinstance(triggers, dict):
            has_pr_trigger = any(t in ("pull_request", "pull_request_target") for t in triggers)

        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            runs_on = job.get("runs-on", "")
            runner_str = str(runs_on)
            if "self-hosted" in runner_str:
                sev = "critical" if has_pr_trigger else "high"
                line = self._find_line(lines, r"self-hosted")
                desc = f"Job '{job_name}' runs on a self-hosted runner."
                if has_pr_trigger:
                    desc += " Combined with PR triggers, this allows untrusted code execution on your infrastructure."
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=sev,
                    file=filepath,
                    line=line,
                    title=self.title,
                    description=desc,
                    remediation="Use GitHub-hosted runners for untrusted code, or restrict self-hosted runners to protected branches."
                ))
        return findings


class UnsafeDefaultsRule(Rule):
    """Detects jobs/steps with continue-on-error or unsafe shell defaults."""

    rule_id = "GHA008"
    title = "Unsafe execution defaults"
    severity = "medium"

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            # Check for continue-on-error at job level
            if job.get("continue-on-error") is True:
                line = self._find_line(lines, r"continue-on-error:\s*true")
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity="medium",
                    file=filepath,
                    line=line,
                    title=f"Job '{job_name}' ignores failures",
                    description=f"Job '{job_name}' has continue-on-error: true. Security-critical steps may fail silently.",
                    remediation="Remove continue-on-error or limit it to non-security-critical steps."
                ))

            for step in (job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                # Check for steps that disable fail-fast
                if step.get("continue-on-error") is True:
                    step_name = step.get("name", "unnamed step")
                    line = self._find_line(lines, r"continue-on-error:\s*true")
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity="low",
                        file=filepath,
                        line=line,
                        title=f"Step '{step_name}' ignores failures",
                        description=f"Step may fail silently. Ensure this doesn't mask security issues.",
                        remediation="Only use continue-on-error for non-critical optional steps."
                    ))
        return findings


class ArtifactPoisoningRule(Rule):
    """Detects artifact upload/download patterns that could enable poisoning."""

    rule_id = "GHA009"
    title = "Artifact trust boundary issue"
    severity = "medium"

    def check(self, workflow: dict, lines: list, filepath: str) -> List[Finding]:
        findings = []
        jobs = workflow.get("jobs", {}) or {}
        uploaders = set()
        downloaders = set()

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for step in (job.get("steps", []) or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if "actions/upload-artifact" in uses:
                    uploaders.add(job_name)
                if "actions/download-artifact" in uses:
                    downloaders.add(job_name)
                    with_block = step.get("with", {}) or {}
                    if not with_block.get("name"):
                        line = self._find_line(lines, r"download-artifact")
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity="medium",
                            file=filepath,
                            line=line,
                            title="Unnamed artifact download",
                            description=f"Job '{job_name}' downloads artifacts without specifying a name. Any job in the workflow run can overwrite artifacts.",
                            remediation="Always specify the 'name' parameter when downloading artifacts."
                        ))

        return findings


def get_all_rules() -> list:
    """Return instances of all available audit rules."""
    from .rules_extended import get_extended_rules
    from .rules_advanced import get_advanced_rules

    base_rules = [
        UnpinnedActionsRule(),
        DangerousTriggerRule(),
        OverlyPermissivePermissionsRule(),
        ScriptInjectionRule(),
        SecretsInLogsRule(),
        ThirdPartyActionRule(),
        SelfHostedRunnerRule(),
        UnsafeDefaultsRule(),
        ArtifactPoisoningRule(),
    ]
    return base_rules + get_extended_rules() + get_advanced_rules()
