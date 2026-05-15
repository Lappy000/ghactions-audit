"""Advanced security rules (GHA013-GHA015).

Covers:
- Injection via actions/github-script with attacker-controlled inputs
- Unsafe use of workflow_dispatch inputs in shell commands
- Secrets passed to actions from untrusted triggers (exfiltration risk)
"""

import re

from .rules import Rule
from .scanner import Finding


class GithubScriptInjectionRule(Rule):
    """Detects potential injection in actions/github-script steps.

    When actions/github-script executes JavaScript that interpolates
    attacker-controlled GitHub context expressions, it enables code
    injection just like shell script injection (GHA004), but via JS eval.
    """

    rule_id = "GHA013"
    title = "Script injection via actions/github-script"
    severity = "critical"

    DANGEROUS_CONTEXTS = [
        r"github\.event\.issue\.title",
        r"github\.event\.issue\.body",
        r"github\.event\.pull_request\.title",
        r"github\.event\.pull_request\.body",
        r"github\.event\.comment\.body",
        r"github\.event\.review\.body",
        r"github\.event\.discussion\.title",
        r"github\.event\.discussion\.body",
        r"github\.head_ref",
        r"github\.event\.head_commit\.message",
        r"github\.event\.head_commit\.author\.name",
        r"github\.event\.commits\.\*\.message",
    ]

    INJECTION_PATTERN = re.compile(r"\$\{\{\s*(" + "|".join(DANGEROUS_CONTEXTS) + r")\s*\}\}")

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
                uses = step.get("uses", "")
                if "actions/github-script" not in uses:
                    continue

                with_block = step.get("with", {}) or {}
                script = with_block.get("script", "")
                if not script:
                    continue

                for match in self.INJECTION_PATTERN.finditer(script):
                    expr = match.group(1)
                    line = self._find_line(lines, re.escape(match.group(0)))
                    step_name = step.get("name", f"step {step_idx}")
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            file=filepath,
                            line=line,
                            title=self.title,
                            description=(
                                f"Expression '${{{{ {expr} }}}}' in job '{job_name}', "
                                f"{step_name} is interpolated into a github-script. "
                                f"Attacker-controlled data enables arbitrary JS execution "
                                f"with the GITHUB_TOKEN."
                            ),
                            remediation=(
                                "Pass untrusted data via an environment variable or "
                                "action input instead of direct interpolation in the "
                                "script body. Use core.getInput() or process.env."
                            ),
                        )
                    )
        return findings


class WorkflowDispatchInjectionRule(Rule):
    """Detects unsafe use of workflow_dispatch inputs in run commands.

    workflow_dispatch inputs are user-provided strings. When interpolated
    directly into shell commands via ${{ github.event.inputs.* }}, they
    enable command injection by any user with write access.
    """

    rule_id = "GHA014"
    title = "Unsafe workflow_dispatch input in shell command"
    severity = "high"

    INPUT_PATTERN = re.compile(r"\$\{\{\s*github\.event\.inputs\.(\w+)\s*\}\}")
    # Also match the newer inputs context
    INPUTS_CONTEXT_PATTERN = re.compile(r"\$\{\{\s*inputs\.(\w+)\s*\}\}")

    def check(self, workflow: dict, lines: list, filepath: str) -> list[Finding]:
        findings = []

        # Only check workflows with workflow_dispatch trigger
        triggers = workflow.get("on", workflow.get(True, {}))
        has_dispatch = self._has_workflow_dispatch(triggers)
        if not has_dispatch:
            return []

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

                for pattern in (self.INPUT_PATTERN, self.INPUTS_CONTEXT_PATTERN):
                    for match in pattern.finditer(run_cmd):
                        input_name = match.group(1)
                        line = self._find_line(lines, re.escape(match.group(0)))
                        step_name = step.get("name", f"step {step_idx}")
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                file=filepath,
                                line=line,
                                title=self.title,
                                description=(
                                    f"Input '{input_name}' is interpolated directly into a "
                                    f"shell command in job '{job_name}', {step_name}. "
                                    f"Any user with write access can inject arbitrary "
                                    f"shell commands via workflow_dispatch."
                                ),
                                remediation=(
                                    "Pass the input via an environment variable: "
                                    f"env: INPUT_{input_name.upper()}: "
                                    "${{ github.event.inputs." + input_name + " }} "
                                    f"and reference $INPUT_{input_name.upper()} in the script."
                                ),
                            )
                        )
        return findings

    def _has_workflow_dispatch(self, triggers) -> bool:
        """Check if workflow_dispatch is among triggers."""
        if isinstance(triggers, str):
            return triggers == "workflow_dispatch"
        elif isinstance(triggers, (list, dict)):
            return "workflow_dispatch" in triggers
        return False


class SecretExfiltrationRiskRule(Rule):
    """Detects secrets accessible from steps triggered by untrusted events.

    When secrets are used in workflows triggered by pull_request_target
    or workflow_run (which run with elevated privileges), they can be
    exfiltrated if the workflow also checks out or executes PR code.
    """

    rule_id = "GHA015"
    title = "Secret accessible in untrusted trigger context"
    severity = "critical"

    UNTRUSTED_TRIGGERS = {"pull_request_target", "workflow_run"}

    SECRETS_PATTERN = re.compile(r"\$\{\{\s*secrets\.(\w+)\s*\}\}")

    def check(self, workflow: dict, lines: list, filepath: str) -> list[Finding]:
        findings = []

        # Check if this workflow uses an untrusted trigger
        triggers = workflow.get("on", workflow.get(True, {}))
        untrusted = self._get_untrusted_triggers(triggers)
        if not untrusted:
            return []

        jobs = workflow.get("jobs", {}) or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            # Check if this job checks out PR code (making secrets exfiltrable)
            if not self._job_runs_untrusted_code(job):
                continue

            steps = job.get("steps", []) or []
            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                # Check run commands for secrets
                run_cmd = step.get("run", "")
                env_block = step.get("env", {}) or {}
                with_block = step.get("with", {}) or {}

                # Check all string values for secret references
                texts_to_check = [run_cmd]
                texts_to_check.extend(str(v) for v in env_block.values())
                texts_to_check.extend(str(v) for v in with_block.values())

                for text in texts_to_check:
                    for match in self.SECRETS_PATTERN.finditer(text):
                        secret_name = match.group(1)
                        if secret_name == "GITHUB_TOKEN":
                            continue  # GITHUB_TOKEN is expected
                        line = self._find_line(lines, re.escape(match.group(0)))
                        step_name = step.get("name", f"step {step_idx}")
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                file=filepath,
                                line=line,
                                title=self.title,
                                description=(
                                    f"Secret '{secret_name}' is used in job '{job_name}', "
                                    f"{step_name} which is triggered by "
                                    f"{', '.join(untrusted)} and runs untrusted code. "
                                    f"An attacker can exfiltrate the secret via a "
                                    f"malicious PR."
                                ),
                                remediation=(
                                    "Move secret-dependent steps to a separate job "
                                    "that does NOT checkout PR code, or use a two-workflow "
                                    "pattern where the privileged workflow only runs "
                                    "trusted code."
                                ),
                            )
                        )
                        break  # One finding per step is enough
                    else:
                        continue
                    break

        return findings

    def _get_untrusted_triggers(self, triggers) -> set:
        """Return set of untrusted triggers present in workflow."""
        if isinstance(triggers, str):
            return {triggers} if triggers in self.UNTRUSTED_TRIGGERS else set()
        elif isinstance(triggers, (list, dict)):
            return {t for t in triggers if t in self.UNTRUSTED_TRIGGERS}
        return set()

    def _job_runs_untrusted_code(self, job: dict) -> bool:
        """Check if a job checks out or executes potentially untrusted code."""
        steps = job.get("steps", []) or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            # Checkout with PR ref
            if "actions/checkout" in uses:
                with_block = step.get("with", {}) or {}
                ref = str(with_block.get("ref", ""))
                if any(x in ref.lower() for x in ("pull_request", "head", "pr")):
                    return True
            # Running arbitrary commands after checkout could be untrusted
            run_cmd = step.get("run", "")
            if run_cmd and "npm" in run_cmd or "make" in run_cmd or "sh " in run_cmd:
                return True
        return False


def get_advanced_rules() -> list:
    """Return instances of all advanced rules."""
    return [
        GithubScriptInjectionRule(),
        WorkflowDispatchInjectionRule(),
        SecretExfiltrationRiskRule(),
    ]
