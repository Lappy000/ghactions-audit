"""Auto-fixer for select audit findings.

Resolves mutable action tags to pinned commit SHAs via the GitHub API.
Generates patched workflow files or unified diffs.
"""

import re
from pathlib import Path
from typing import Optional

import requests

# GitHub API base
GITHUB_API = "https://api.github.com"

# Cache resolved SHAs to avoid redundant API calls
_sha_cache: dict[str, str] = {}


def resolve_action_sha(action_ref: str, token: Optional[str] = None) -> Optional[str]:
    """Resolve an action@tag reference to action@sha.

    Args:
        action_ref: e.g. "actions/checkout@v4"
        token: Optional GitHub token for higher rate limits.

    Returns:
        The full 40-char commit SHA, or None if resolution fails.
    """
    if "@" not in action_ref:
        return None

    action_path, tag = action_ref.split("@", 1)

    # Already a SHA
    if re.match(r"^[a-f0-9]{40}$", tag):
        return tag

    cache_key = f"{action_path}@{tag}"
    if cache_key in _sha_cache:
        return _sha_cache[cache_key]

    # Handle nested actions (e.g. aws-actions/configure-aws-credentials)
    parts = action_path.split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Try resolving as a git ref (tag or branch)
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/tags/{tag}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            obj = data.get("object", {})
            sha = obj.get("sha", "")
            # If it's an annotated tag, we need to dereference it
            if obj.get("type") == "tag":
                tag_url = obj.get("url", "")
                if tag_url:
                    tag_resp = requests.get(tag_url, headers=headers, timeout=10)
                    if tag_resp.status_code == 200:
                        sha = tag_resp.json().get("object", {}).get("sha", sha)
            if sha and len(sha) == 40:
                _sha_cache[cache_key] = sha
                return sha

        # Fall back to branches
        url = f"{GITHUB_API}/repos/{owner}/{repo}/git/ref/heads/{tag}"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            sha = resp.json().get("object", {}).get("sha", "")
            if sha and len(sha) == 40:
                _sha_cache[cache_key] = sha
                return sha

    except requests.RequestException:
        return None

    return None


def fix_unpinned_actions(
    filepath: Path,
    token: Optional[str] = None,
    dry_run: bool = False,
) -> list[tuple[str, str, str]]:
    """Fix unpinned action references in a workflow file.

    Args:
        filepath: Path to the workflow YAML file.
        token: Optional GitHub token for API access.
        dry_run: If True, return changes but don't write to disk.

    Returns:
        List of (original_ref, pinned_ref, sha) tuples for each fix applied.
    """
    content = filepath.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    fixes = []

    # Pattern to match: uses: org/repo@tag (not already a SHA)
    uses_re = re.compile(r"(\s*uses:\s*)([^\s#]+)@([^\s#]+)")

    sha_pattern = re.compile(r"^[a-f0-9]{40}$")

    new_lines = []
    for line in lines:
        match = uses_re.search(line)
        if match:
            prefix = match.group(1)
            action_path = match.group(2)
            tag = match.group(3)

            if action_path.startswith("./") or sha_pattern.match(tag):
                new_lines.append(line)
                continue

            sha = resolve_action_sha(f"{action_path}@{tag}", token=token)
            if sha:
                # Replace tag with SHA, add comment with original tag
                old_ref = f"{action_path}@{tag}"
                new_ref = f"{action_path}@{sha}"
                comment = f"  # {tag}"
                new_line = line[: match.start()] + f"{prefix}{new_ref}{comment}\n"
                new_lines.append(new_line)
                fixes.append((old_ref, new_ref, sha))
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if fixes and not dry_run:
        filepath.write_text("".join(new_lines), encoding="utf-8")

    return fixes


def generate_diff(
    filepath: Path,
    token: Optional[str] = None,
) -> Optional[str]:
    """Generate a unified diff showing what --fix would change.

    Returns:
        Unified diff string, or None if no changes needed.
    """
    import difflib

    content = filepath.read_text(encoding="utf-8")
    original_lines = content.splitlines(keepends=True)

    # Simulate fix
    fixes = fix_unpinned_actions(filepath, token=token, dry_run=True)
    if not fixes:
        return None

    # Rebuild the fixed version for diff
    uses_re = re.compile(r"(\s*uses:\s*)([^\s#]+)@([^\s#]+)")
    sha_pattern = re.compile(r"^[a-f0-9]{40}$")

    new_lines = []
    for line in original_lines:
        match = uses_re.search(line)
        if match:
            action_path = match.group(2)
            tag = match.group(3)
            if not action_path.startswith("./") and not sha_pattern.match(tag):
                sha = resolve_action_sha(f"{action_path}@{tag}", token=token)
                if sha:
                    prefix = match.group(1)
                    new_ref = f"{action_path}@{sha}"
                    comment = f"  # {tag}"
                    new_line = line[: match.start()] + f"{prefix}{new_ref}{comment}\n"
                    new_lines.append(new_line)
                    continue
        new_lines.append(line)

    diff = difflib.unified_diff(
        original_lines,
        new_lines,
        fromfile=f"a/{filepath.name}",
        tofile=f"b/{filepath.name}",
    )
    diff_text = "".join(diff)
    return diff_text if diff_text else None
