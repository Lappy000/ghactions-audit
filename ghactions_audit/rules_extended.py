"""Additional security rules (GHA010-GHA012).

Covers environment variable injection, cache poisoning,
and OIDC token misconfiguration vectors.
"""

import re

from .rules import Rule
from .scanner import Finding


class EnvironmentInjectionRule(Rule):
    """Detects unsafe environment variable setting from untrusted inputs.

    Setting GITHUB_ENV or GITHUB_PATH from attacker-controlled data enables
    environment variable injection, which can hijack subsequent steps.
    """

    rule_id = "GHA010"
    title = "Environment variable injection"
    severity = "critical"

    # Patterns that write to GITHUB_ENV or GITHUB_PATH using attacker-controlled input
    ENV_WRITE_PATTERNS = [
        # echo "VAR=value" >> $GITHUB_ENV with attacker input
        re.compile(r">>\s*\$GITHUB_ENV", re.IGNORECASE),
        re.compile(r">>\s*\$GITHUB_PATH", re.IGNORECASE),
        re.compile(r'>>\s*"\$GITHUB_ENV"', re.IGNORECASE),
        re.compile(r'>>\s*"\$GITHUB_PATH"', re.IGNORECASE),
        re.compile(r">>\s*\$\{GITHUB_ENV\}", re.IGNORECASE),
        re.compile(r">>\s*\$\{GITHUB_PATH\}", re.IGNORECASE),
    ]

    DANGEROUS_INPUTS = re.compile(
        r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|discussion)"
        r"|github\.head_ref|github\.event\.head_commit)",
    )

    def check(self, workflow: dict, lines: list, filepath: str) -> list[Finding]:
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

                has_env_write = any(p.search(run_cmd) for p in self.ENV_WRITE_PATTERNS)
                has_dangerous_input = self.DANGEROUS_INPUTS.search(run_cmd)

                if has_env_write and has_dangerous_input:
                    step_name = step.get("name", f"step {step_idx}")
                    line = self._find_line(lines, r"GITHUB_ENV|GITHUB_PATH")
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            file=filepath,
                            line=line,
                            title=self.title,
                            description=(
                                f"Job '{job_name}', {step_name} writes attacker-controlled "
                                f"data to GITHUB_ENV/GITHUB_PATH. This enables environment "
                                f"variable injection that hijacks subsequent steps."
                            ),
                            remediation=(
                                "Sanitize inputs before writing to GITHUB_ENV. Use "
                                "intermediate variables and validate content. Consider "
                                "using step outputs instead of environment files."
                            ),
                        )
                    )
                elif has_env_write:
                    # Still flag GITHUB_ENV writes as medium even without obvious injection
                    step_name = step.get("name", f"step {step_idx}")
                    line = self._find_line(lines, r"GITHUB_ENV|GITHUB_PATH")
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity="medium",
                            file=filepath,
                            line=line,
                            title="GITHUB_ENV/GITHUB_PATH write",
                            description=(
                                f"Job '{job_name}', {step_name} writes to GITHUB_ENV or "
                                f"GITHUB_PATH. Verify no untrusted data flows into this write."
                            ),
                            remediation=(
                                "Audit the data source. If it includes any external input "
                                "(PR title, branch name, etc.), sanitize before writing."
                            ),
                        )
                    )

        return findings


class CachePoisoningRule(Rule):
    """Detects cache configurations vulnerable to poisoning attacks.

    Caches shared across branches or workflows can be poisoned by
    malicious PRs to inject code into protected branch builds.
    """

    rule_id = "GHA011"
    title = "Cache poisoning risk"
    severity = "high"

    def check(self, workflow: dict, lines: list, filepath: str) -> list[Finding]:
        findings = []
        triggers = workflow.get("on", workflow.get(True, {}))

        # Determine if workflow runs on PRs (makes cache poisoning viable)
        runs_on_pr = self._runs_on_pr(triggers)

        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps", []) or []
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")

                # Check actions/cache usage
                if "actions/cache" in uses:
                    with_block = step.get("with", {}) or {}
                    key = with_block.get("key", "")
                    with_block.get("restore-keys", "")

                    # If cache key doesn't include a branch/ref discriminator
                    # and the workflow accepts PRs, it's vulnerable
                    if runs_on_pr and not self._key_has_ref_scope(key):
                        line = self._find_line(lines, r"actions/cache")
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                file=filepath,
                                line=line,
                                title=self.title,
                                description=(
                                    f"Job '{job_name}' uses actions/cache with a key that "
                                    f"may not be branch-scoped. On PR-triggered workflows, "
                                    f"a malicious PR can poison the cache for the default branch."
                                ),
                                remediation=(
                                    "Include ${{ github.ref }} or branch name in the cache key. "
                                    "Consider using cache isolation per PR."
                                ),
                            )
                        )

                # Check setup-node, setup-python with caching
                if any(x in uses for x in ("setup-node", "setup-python", "setup-go")):
                    with_block = step.get("with", {}) or {}
                    if with_block.get("cache") and runs_on_pr:
                        line = self._find_line(lines, re.escape(uses.split("@")[0]))
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity="medium",
                                file=filepath,
                                line=line,
                                title="Built-in cache on PR workflow",
                                description=(
                                    f"Job '{job_name}' uses built-in caching with "
                                    f"'{uses.split('@')[0]}' on a PR-triggered workflow. "
                                    f"Built-in caches are scoped by branch but verify "
                                    f"restore-keys don't cross trust boundaries."
                                ),
                                remediation=(
                                    "Review cache scope. GitHub caches are branch-scoped "
                                    "but restore-keys can pull from the default branch."
                                ),
                            )
                        )

        return findings

    def _runs_on_pr(self, triggers) -> bool:
        """Check if workflow is triggered by pull requests."""
        if isinstance(triggers, str):
            return triggers in ("pull_request", "pull_request_target")
        elif isinstance(triggers, (list, dict)):
            return any(t in ("pull_request", "pull_request_target") for t in triggers)
        return False

    def _key_has_ref_scope(self, key: str) -> bool:
        """Check if a cache key includes branch/ref scoping."""
        ref_indicators = [
            "github.ref",
            "github.head_ref",
            "github.base_ref",
            "runner.os",  # not branch-scoping, but partial
        ]
        return any(indicator in key for indicator in ref_indicators[:3])


class OIDCMisconfigRule(Rule):
    """Detects OIDC token permission grants without proper audience restriction.

    OIDC tokens (id-token: write) without audience restrictions can be
    used to authenticate to unintended cloud providers.
    """

    rule_id = "GHA012"
    title = "OIDC token misconfiguration"
    severity = "high"

    def check(self, workflow: dict, lines: list, filepath: str) -> list[Finding]:
        findings = []

        # Check if id-token permission is granted
        top_perms = workflow.get("permissions", {})
        has_oidc = False

        if isinstance(top_perms, dict) and top_perms.get("id-token") == "write":
            has_oidc = True

        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            job_perms = job.get("permissions", {})
            job_has_oidc = has_oidc
            if isinstance(job_perms, dict) and job_perms.get("id-token") == "write":
                job_has_oidc = True

            if not job_has_oidc:
                continue

            # Check if OIDC is used with proper audience configuration
            steps = job.get("steps", []) or []
            oidc_consumer_found = False
            audience_configured = False

            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                with_block = step.get("with", {}) or {}

                # Known OIDC consumers
                if any(
                    x in uses
                    for x in (
                        "aws-actions/configure-aws-credentials",
                        "azure/login",
                        "google-github-actions/auth",
                    )
                ):
                    oidc_consumer_found = True
                    if with_block.get("audience"):
                        audience_configured = True

            if job_has_oidc and not oidc_consumer_found:
                line = self._find_line(lines, r"id-token:\s*write")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        file=filepath,
                        line=line,
                        title="OIDC permission without consumer",
                        description=(
                            f"Job '{job_name}' requests id-token:write but has no "
                            f"recognized OIDC consumer action. The token may be "
                            f"exposed to untrusted steps or exfiltrated."
                        ),
                        remediation=(
                            "Remove id-token:write if unused, or ensure only "
                            "trusted steps can access the OIDC token."
                        ),
                    )
                )
            elif job_has_oidc and oidc_consumer_found and not audience_configured:
                line = self._find_line(lines, r"id-token:\s*write")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity="medium",
                        file=filepath,
                        line=line,
                        title="OIDC without audience restriction",
                        description=(
                            f"Job '{job_name}' uses OIDC authentication without "
                            f"setting a custom audience. Default audience may be "
                            f"too broad for your trust model."
                        ),
                        remediation=(
                            "Set the 'audience' parameter on your cloud auth action "
                            "to restrict token acceptance."
                        ),
                    )
                )

        return findings


def get_extended_rules() -> list:
    """Return instances of all extended rules."""
    return [
        EnvironmentInjectionRule(),
        CachePoisoningRule(),
        OIDCMisconfigRule(),
    ]
