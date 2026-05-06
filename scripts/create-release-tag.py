#!/usr/bin/env python3
"""
create and push userauth-<sha>-<n> tags
Checks that the version in ooniauth-py is consistent before creating the new tag
"""

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

TAG_PREFIX = "userauth"
PYPI_JSON_URL = "https://pypi.org/pypi/ooniauth-py/json"

CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"

REPO_ROOT = Path(__file__).resolve().parent.parent


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def version_tuple(v: str) -> tuple[int, ...]:
    """Numeric dotted version -> tuple for lexicographic compare"""
    parts = v.strip().strip("v").split(".")
    if not parts or any(not p.isdigit() for p in parts):
        raise ValueError(f"expected dotted numeric version, got {v}")
    return tuple(int(p) for p in parts)


def parse_cargo_version(cargo_toml: Path) -> str:
    text = cargo_toml.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise SystemExit(f"Error: could not parse version from {cargo_toml}")
    return m.group(1)


def fetch_pypi_version(url: str = PYPI_JSON_URL) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "create-release-tag.py"})
    with urllib.request.urlopen(req, timeout=20) as response:
        data = json.load(response)
    return str(data["info"]["version"])


def max_release_number(tags: list[str]) -> int:
    pat = re.compile(rf"^{re.escape(TAG_PREFIX)}-[^-]+-(\d+)$")
    best = 0
    for line in tags:
        t = line.strip()
        m = pat.match(t)
        if m:
            best = max(best, int(m.group(1)))
    return best


def tag_exists_remote(tag: str) -> bool:
    # ls-remote exits 0 with empty output when the ref is missing.
    out = git(
        "ls-remote",
        "--tags",
        "origin",
        f"refs/tags/{tag}",
    )
    return bool(out.stdout.strip())


def vstr(v_tuple: tuple[int, ...]) -> str:
    return ".".join(map(str, v_tuple))


def main() -> None:
    current_branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    commit_sha = git("rev-parse", "--short", "HEAD").stdout.strip()

    tags_out = git("tag", "--list", f"{TAG_PREFIX}-*").stdout
    tags = [ln for ln in tags_out.splitlines() if ln.strip()]
    max_n = max_release_number(tags)
    next_n = max_n + 1
    tag_name = f"{TAG_PREFIX}-{commit_sha}-{next_n}"

    # returns err if tag is unknown, which is what we want
    tag_exists = git("rev-parse", tag_name, check=False).returncode == 0
    if tag_exists:
        # tag_name can contain \n so we use `!r` at the end to print the
        # sequence instead of a line jump
        eprint(f"Error: tag {tag_name!r} already exists locally.")
        sys.exit(1)

    if tag_exists_remote(tag_name):
        eprint(f"Error: tag {tag_name!r} already exists on origin.")
        sys.exit(1)

    cargo_toml = REPO_ROOT / "ooniauth-py" / "Cargo.toml"
    if not cargo_toml.is_file():
        eprint(f"Error: Missing ooniauth-py cargo.toml file :{cargo_toml}")
        sys.exit(1)

    local_version = parse_cargo_version(cargo_toml)

    print("Checking last version from PyPi...")
    try:
        pypi_version = fetch_pypi_version()
    except Exception as e:
        eprint(f"Error: failed to fetch PyPI version: {e}")
        sys.exit(1)

    try:
        local_version = version_tuple(local_version)
        pypi_version = version_tuple(pypi_version)
    except ValueError as e:
        eprint(f"Error: {e}")
        sys.exit(1)

    if local_version <= pypi_version:
        eprint(
            f"{RED}ERROR{RESET}: Local ooniauth-py version must be greater than PyPI, "
            "bump ooniauth-py/Cargo.toml before releasing.",
        )
        eprint(f"  Local: {vstr(local_version)}")
        eprint(f"  PyPI:  {vstr(pypi_version)}")
        sys.exit(1)

    print("Version number OK!")

    print("Release tag preview:")
    print(f"  Tag scheme:     {TAG_PREFIX}-<shortsha>-<release_number>")
    print(f"  Release number: {next_n}")
    print(f"  Tag:            {CYAN}{tag_name}{RESET}")
    if current_branch == "main":
        print(f"  Branch:         {current_branch}")
    else:
        print(f"  Branch:         {RED}{current_branch} (WARNING: not main){RESET}")
    print(f"  Commit:         {commit_sha}")
    print(f"  ooniauth-py:    {vstr(local_version)} (PyPI: {vstr(pypi_version)})")
    print()
    if current_branch != "main":
        print(
            f"  {YELLOW}WARNING: current branch is '{current_branch}' (not main): "
            f"commit {commit_sha} is not in main{RESET}"
        )

    prompt = f"Create and push tag {CYAN} {tag_name} {RESET} to origin? [y/N] "
    try:
        answer = input(prompt).strip().lower()
    except KeyboardInterrupt as _:
        answer = 'n'
        print("\n")
    if answer not in ("y", "yes"):
        print("Aborted.")
        return

    git("tag", "-a", tag_name, "-m", f"Release {tag_name}")
    git("push", "origin", tag_name)
    print(f"Done: pushed {CYAN}{tag_name}{RESET}")


if __name__ == "__main__":
    main()
