"""GitHub API client using gh CLI."""

import json
import subprocess
import sys
import time
import re
import base64

# Dependency file patterns to search for
DEPENDENCY_FILE_PATTERNS = [
    re.compile(r"(^|/)requirements.*\.txt$", re.IGNORECASE),
    re.compile(r"(^|/)pyproject\.toml$"),
    re.compile(r"(^|/)Pipfile(\.lock)?$"),
    re.compile(r"(^|/)poetry\.lock$"),
    re.compile(r"(^|/)setup\.(py|cfg)$"),
    re.compile(r"(^|/)Dockerfile"),
]


# Allowlist of permitted gh subcommands and API path prefixes.
# Only read-only operations are allowed.
_ALLOWED_GH_SUBCOMMANDS = {"api", "auth"}
_ALLOWED_API_PATH_PREFIXES = (
    "/user",
    "/repos/",
    "/search/",
)
_FORBIDDEN_API_FLAGS = {"-X", "--method"}


def _validate_gh_args(args):
    """Ensure gh arguments are read-only operations only.

    Raises ValueError if a disallowed subcommand, API path, or HTTP method
    override is detected.
    """
    if not args:
        raise ValueError("Empty gh arguments")

    subcommand = args[0]
    if subcommand not in _ALLOWED_GH_SUBCOMMANDS:
        raise ValueError(f"Disallowed gh subcommand: {subcommand}")

    # Check for forbidden flags that could change HTTP method
    for arg in args:
        if arg in _FORBIDDEN_API_FLAGS:
            raise ValueError(
                f"Disallowed flag '{arg}': only GET (read-only) requests are permitted"
            )

    # For 'api' subcommand, validate the endpoint path
    if subcommand == "api":
        # Find the API path (first positional arg after 'api')
        api_path = None
        skip_next = False
        for arg in args[1:]:
            if skip_next:
                skip_next = False
                continue
            if arg in ("--jq", "-q", "--template", "-t", "--paginate", "-p",
                       "--hostname", "--cache", "-H", "--header", "-f", "--field",
                       "-F", "--raw-field"):
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            api_path = arg
            break

        if api_path and not any(
            api_path.startswith(prefix) for prefix in _ALLOWED_API_PATH_PREFIXES
        ):
            raise ValueError(
                f"Disallowed API path: {api_path}. "
                f"Allowed prefixes: {_ALLOWED_API_PATH_PREFIXES}"
            )


def _run_gh(args, ignore_errors=False):
    """Run a gh CLI command and return parsed JSON output.

    Only read-only (GET) operations are permitted.
    Handles paginated output that may contain multiple JSON arrays/objects.
    """
    _validate_gh_args(args)
    cmd = ["gh"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if ignore_errors:
            return None
        # Handle rate limiting
        if "rate limit" in result.stderr.lower() or "403" in result.stderr:
            print("  Rate limited, waiting 60s...", file=sys.stderr)
            time.sleep(60)
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return None
        else:
            return None
    if not result.stdout.strip():
        return None

    # Handle paginated output: gh --paginate may concatenate multiple JSON arrays
    output = result.stdout.strip()
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # Try to parse as multiple JSON objects/arrays concatenated
        decoder = json.JSONDecoder()
        results = []
        idx = 0
        while idx < len(output):
            # Skip whitespace
            while idx < len(output) and output[idx] in ' \t\n\r':
                idx += 1
            if idx >= len(output):
                break
            obj, end_idx = decoder.raw_decode(output, idx)
            if isinstance(obj, list):
                results.extend(obj)
            else:
                results.append(obj)
            idx = end_idx
        return results if results else None


def check_auth():
    """Verify gh CLI is authenticated. Returns username or exits."""
    result = subprocess.run(
        ["gh", "auth", "status"], capture_output=True, text=True
    )
    if result.returncode != 0:
        print("Error: gh CLI is not authenticated.", file=sys.stderr)
        print("Run 'gh auth login' first.", file=sys.stderr)
        sys.exit(1)
    # --jq returns raw string, not JSON
    result = subprocess.run(
        ["gh", "api", "/user", "--jq", ".login"],
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def get_user_repos(username=None, repos_filter=None):
    """Get all repositories for the authenticated user.

    Args:
        username: GitHub username (used for filtering).
        repos_filter: Optional list of repo names to filter.

    Returns:
        List of repo dicts with 'full_name' and 'default_branch'.
    """
    data = _run_gh([
        "api", "/user/repos",
        "--paginate",
        "--jq", '[.[] | {full_name: .full_name, default_branch: .default_branch, fork: .fork, archived: .archived}]',
    ])
    if not data:
        return []

    repos = data
    if repos_filter:
        filter_set = {r.strip() for r in repos_filter}
        repos = [
            r for r in repos
            if r["full_name"] in filter_set
            or r["full_name"].split("/")[-1] in filter_set
        ]

    return repos


def get_dependency_files(owner_repo, default_branch):
    """Get dependency file paths from a repository using Tree API.

    Returns:
        List of file paths that match dependency file patterns.
    """
    data = _run_gh([
        "api",
        f"/repos/{owner_repo}/git/trees/{default_branch}?recursive=1",
    ], ignore_errors=True)

    if not data or "tree" not in data:
        return []

    paths = [item["path"] for item in data["tree"] if item["type"] == "blob"]
    matched = []
    for path in paths:
        for pattern in DEPENDENCY_FILE_PATTERNS:
            if pattern.search(path):
                matched.append(path)
                break

    return matched


def get_file_content(owner_repo, file_path):
    """Get decoded file content from a repository.

    Returns:
        File content as string, or None on failure.
    """
    data = _run_gh([
        "api", f"/repos/{owner_repo}/contents/{file_path}",
    ], ignore_errors=True)

    if not data or "content" not in data:
        return None

    try:
        content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return content
    except Exception:
        return None
