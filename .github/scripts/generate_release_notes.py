#!/usr/bin/env python3
"""
Generate Markdown release notes:
1. Extracts curated notes from CHANGELOG.md for the given version if available.
2. Otherwise, parses Conventional Commits from git log between the previous tag
   and current tag/HEAD, grouped into clean markdown sections with GitHub commit links.
"""
import os
import re
import subprocess
import sys


def run_git(*args, cwd=None):
    res = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return ""
    return res.stdout.strip()


def get_repo(cwd=None):
    repo = os.environ.get("GITHUB_REPOSITORY")
    if repo:
        return repo.strip()
    remote_url = run_git("remote", "get-url", "origin", cwd=cwd)
    match = re.search(r"github\.com[:/]([^/]+/[^/.]+)", remote_url)
    if match:
        return match.group(1).rstrip(".git")
    return None


def extract_from_changelog(version, changelog_path="CHANGELOG.md"):
    if not os.path.isfile(changelog_path):
        return None
    try:
        with open(changelog_path, "r", encoding="utf-8") as f:
            content = f.read()
        clean_version = version.lstrip("v")
        pattern = rf"## \[{re.escape(clean_version)}\][^\n]*\n(.*?)(?=\n## \[|\Z)"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            notes = match.group(1).strip()
            if notes:
                return f"## What's Changed\n\n{notes}"
    except Exception as e:
        sys.stderr.write(f"Warning: Failed reading {changelog_path}: {e}\n")
    return None


def get_previous_tag(current_tag, cwd=None):
    # Try git describe on current_tag^
    prev = run_git("describe", "--tags", "--abbrev=0", f"{current_tag}^", cwd=cwd)
    if prev:
        return prev

    # Try git describe on HEAD^
    prev = run_git("describe", "--tags", "--abbrev=0", "HEAD^", cwd=cwd)
    if prev:
        return prev

    # Fall back to tag sort
    tags = run_git("tag", "--sort=-v:refname", cwd=cwd).splitlines()
    tags = [t.strip() for t in tags if t.strip()]
    if current_tag in tags:
        idx = tags.index(current_tag)
        if idx + 1 < len(tags):
            return tags[idx + 1]
    elif tags:
        return tags[0]

    return None


def get_commits(current_tag, prev_tag=None, cwd=None):
    rev_range = f"{prev_tag}..{current_tag}" if prev_tag else current_tag
    log_output = run_git("log", rev_range, "--pretty=format:%h%x09%H%x09%s", cwd=cwd)
    if not log_output:
        return []

    commits = []
    for line in log_output.splitlines():
        if not line:
            continue
        parts = line.split("\t", 2)
        if len(parts) == 3:
            commits.append((parts[0], parts[1], parts[2]))
    return commits


def format_commits(repo, commits):
    categories = [
        ("🚀 Features", re.compile(r"^feat(\(.*\))?:", re.IGNORECASE)),
        ("🐛 Bug Fixes", re.compile(r"^fix(\(.*\))?:", re.IGNORECASE)),
        ("⚡ Performance Improvements", re.compile(r"^perf(\(.*\))?:", re.IGNORECASE)),
        ("📚 Documentation", re.compile(r"^docs(\(.*\))?:", re.IGNORECASE)),
        ("🔧 Maintenance & Tooling", re.compile(r"^(chore|refactor|test|ci|style|build)(\(.*\))?:", re.IGNORECASE)),
    ]

    grouped = {title: [] for title, _ in categories}
    other_items = []

    for short_sha, long_sha, subject in commits:
        if re.match(r"^chore\(release\):", subject, re.IGNORECASE) or re.match(r"^bump version", subject, re.IGNORECASE):
            continue

        matched = False
        for title, regex in categories:
            if regex.match(subject):
                grouped[title].append((short_sha, long_sha, subject))
                matched = True
                break
        if not matched:
            other_items.append((short_sha, long_sha, subject))

    if other_items:
        grouped["📦 Other Changes"] = other_items

    lines = ["## What's Changed\n"]
    total_items = 0

    for title, items in grouped.items():
        if not items:
            continue
        lines.append(f"### {title}\n")
        for short_sha, long_sha, subject in items:
            total_items += 1
            if repo:
                commit_link = f"https://github.com/{repo}/commit/{long_sha}"
                lines.append(f"- {subject} in [`{short_sha}`]({commit_link})")
            else:
                lines.append(f"- {subject} (`{short_sha}`)")
        lines.append("")

    if total_items == 0:
        lines.append("No significant commit changes in this release.\n")

    return "\n".join(lines)


def main():
    current_tag = sys.argv[1] if len(sys.argv) > 1 else None
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not current_tag:
        current_tag = run_git("describe", "--tags", "--exact-match")
        if not current_tag:
            current_tag = "HEAD"

    version = current_tag.lstrip("v")
    notes = extract_from_changelog(version)

    if not notes:
        repo = get_repo()
        prev_tag = get_previous_tag(current_tag)
        commits = get_commits(current_tag, prev_tag)
        notes = format_commits(repo, commits)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(notes + "\n")
    else:
        print(notes)


if __name__ == "__main__":
    main()
