"""
GitHub Agent: applies generated security fixes directly to the target repository.
Commits diffs to a specified branch (or creates a new security-fix branch).
"""

import re
import os
import base64
from pathlib import Path
from typing import Optional
from github import Github, GithubException  # pip install PyGithub


def _parse_diff_from_advice(advice: str) -> Optional[tuple[str, str, str]]:
    """
    Extract (filename, old_content_fragment, new_content_fragment) from Claude's diff block.
    Returns None if no parseable diff found.
    """
    # Find diff code block
    diff_match = re.search(r"```diff\n(.*?)```", advice, re.DOTALL)
    if not diff_match:
        return None

    diff_text = diff_match.group(1)

    # Extract filename from diff header (--- a/path or +++ b/path)
    file_match = re.search(r"(?:---|\+\+\+)\s+[ab]/(.+)", diff_text)
    filename = file_match.group(1).strip() if file_match else None
    if not filename:
        return None

    removed = []
    added = []
    for line in diff_text.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])

    return filename, "\n".join(removed), "\n".join(added)


def _apply_patch_to_content(original: str, old_fragment: str, new_fragment: str) -> Optional[str]:
    """Apply a simple text replacement patch to file content."""
    if old_fragment.strip() in original:
        return original.replace(old_fragment.strip(), new_fragment.strip(), 1)
    # Try line-by-line fuzzy match
    old_lines = [l.strip() for l in old_fragment.splitlines() if l.strip()]
    new_lines = new_fragment.splitlines()
    result_lines = original.splitlines()
    for i in range(len(result_lines)):
        window = [l.strip() for l in result_lines[i:i+len(old_lines)]]
        if window == old_lines:
            result_lines[i:i+len(old_lines)] = new_lines
            return "\n".join(result_lines)
    return None  # patch didn't apply


def commit_fix(
    repo_url: str,
    github_token: str,
    finding_dict: dict,
    target_branch: str = "main",
    author_name: str = "Security Review Bot",
    author_email: str = "security-bot@example.com",
) -> dict:
    """
    Apply a single finding's fix_suggestion diff to the GitHub repo.
    Returns a result dict with status and commit URL (or error).
    """
    advice = finding_dict.get("fix_suggestion", "")
    if not advice:
        return {"status": "skipped", "reason": "no fix_suggestion"}

    parsed = _parse_diff_from_advice(advice)
    if not parsed:
        return {"status": "skipped", "reason": "no parseable diff in advice"}

    filename, old_fragment, new_fragment = parsed

    # Extract owner/repo from URL
    match = re.search(r"github\.com[:/](.+?)/(.+?)(?:\.git)?$", repo_url)
    if not match:
        return {"status": "error", "reason": f"Cannot parse GitHub URL: {repo_url}"}
    owner, repo_name = match.group(1), match.group(2)

    g = Github(github_token)
    try:
        repo = g.get_repo(f"{owner}/{repo_name}")
    except GithubException as e:
        return {"status": "error", "reason": str(e)}

    # Get current file content
    try:
        file_obj = repo.get_contents(filename, ref=target_branch)
        original_content = file_obj.decoded_content.decode("utf-8")
        current_sha = file_obj.sha
    except GithubException as e:
        return {"status": "error", "reason": f"Cannot fetch {filename}: {e}"}

    # Apply patch
    patched = _apply_patch_to_content(original_content, old_fragment, new_fragment)
    if patched is None:
        return {"status": "skipped", "reason": f"Patch did not apply cleanly to {filename}"}
    if patched == original_content:
        return {"status": "skipped", "reason": "No change after applying patch"}

    # Extract commit message from advice
    msg_match = re.search(r"##\s*Commit Message\s*\n(.+)", advice)
    commit_msg = msg_match.group(1).strip() if msg_match else (
        f"security: fix {finding_dict.get('cwe', 'vulnerability')} in {filename}"
    )
    commit_msg += f"\n\nRule: {finding_dict.get('rule_id')}\n"
    if finding_dict.get("attack_technique"):
        commit_msg += f"MITRE ATT&CK: {finding_dict['attack_technique']} ({finding_dict.get('attack_name')})\n"
    if finding_dict.get("cwe"):
        commit_msg += f"CWE: {finding_dict['cwe']}\n"

    try:
        result = repo.update_file(
            path=filename,
            message=commit_msg,
            content=patched,
            sha=current_sha,
            branch=target_branch,
            author={"name": author_name, "email": author_email},
            committer={"name": author_name, "email": author_email},
        )
        commit_url = result["commit"].html_url
        print(f"    [+] Committed fix: {commit_url}")
        return {"status": "committed", "file": filename, "commit_url": commit_url}
    except GithubException as e:
        return {"status": "error", "reason": str(e)}


def commit_all_fixes(
    repo_url: str,
    github_token: str,
    enriched_findings: list[dict],
    target_branch: str = "main",
    dry_run: bool = True,
) -> list[dict]:
    """
    Iterate over enriched findings and commit applicable fixes.
    dry_run=True prints what would be committed without touching GitHub.
    """
    results = []
    committable = [f for f in enriched_findings if f.get("fix_suggestion")]

    print(f"\n[*] {'DRY RUN: ' if dry_run else ''}Committing {len(committable)} fixes to {repo_url} ({target_branch})")

    for finding in committable:
        label = f"{finding.get('rule_id')} @ {finding.get('file')}:{finding.get('line_start')}"
        if dry_run:
            has_diff = bool(re.search(r"```diff", finding.get("fix_suggestion", "")))
            print(f"    [dry-run] Would commit: {label} (diff={'yes' if has_diff else 'no'})")
            results.append({"status": "dry_run", "finding": label})
        else:
            r = commit_fix(repo_url, github_token, finding, target_branch)
            r["finding"] = label
            results.append(r)

    return results
