"""Parse dependency files and detect vulnerable litellm versions."""

import re

# Vulnerable versions
VULNERABLE_VERSIONS = {"1.82.7", "1.82.8"}

# Direct target package
DIRECT_PACKAGE = "litellm"

# Indirect dependency packages (use litellm internally)
INDIRECT_PACKAGES = {"openhands", "dspy", "agentops", "langfuse", "mlflow"}

ALL_PACKAGES = {DIRECT_PACKAGE} | INDIRECT_PACKAGES

# Verdict constants
VULNERABLE = "VULNERABLE"
SAFE = "SAFE"
WARNING = "WARNING"
CHECK_INDIRECT = "CHECK_INDIRECT"


def parse_requirements_txt(content):
    """Parse requirements.txt format.

    Returns list of (package_name, version_or_None).
    """
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Remove inline comments
        line = line.split("#")[0].strip()
        # Match: package==version, package>=version, package~=version, etc.
        m = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?", line)
        if m:
            pkg = m.group(1).lower().replace("-", "_")
            ver = m.group(2)
            if pkg.replace("_", "-") in ALL_PACKAGES or pkg in ALL_PACKAGES:
                results.append((pkg, ver))
    return results


def parse_pyproject_toml(content):
    """Parse pyproject.toml for dependencies (simple regex-based)."""
    results = []
    # Match patterns like: "litellm>=1.0", "litellm==1.82.7", "litellm"
    for pkg in ALL_PACKAGES:
        # Look for package in dependencies sections
        patterns = [
            rf'["\']({re.escape(pkg)})\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?["\']',
            rf'^{re.escape(pkg)}\s*=\s*["\']([^"\']*)["\']',
            rf'^{re.escape(pkg)}\s*=\s*\{{[^}}]*version\s*=\s*["\']([^"\']*)["\']',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                groups = m.groups()
                if len(groups) >= 2:
                    ver = groups[1]
                else:
                    ver_str = groups[0] if groups else None
                    ver_m = re.search(r"[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*)", ver_str or "")
                    ver = ver_m.group(1) if ver_m else None
                results.append((pkg, ver))
    return results


def parse_pipfile(content):
    """Parse Pipfile format."""
    results = []
    for pkg in ALL_PACKAGES:
        patterns = [
            rf'^{re.escape(pkg)}\s*=\s*["\']([^"\']*)["\']',
            rf'^{re.escape(pkg)}\s*=\s*["\']?\*["\']?',
            rf'^{re.escape(pkg)}\s*=\s*\{{[^}}]*version\s*=\s*["\']([^"\']*)["\']',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                groups = m.groups()
                if groups and groups[0]:
                    ver_m = re.search(r"[0-9][0-9a-zA-Z._-]*", groups[0])
                    ver = ver_m.group(0) if ver_m else None
                else:
                    ver = None
                results.append((pkg, ver))
    return results


def parse_pipfile_lock(content):
    """Parse Pipfile.lock (JSON format)."""
    import json
    results = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return results
    for section in ["default", "develop"]:
        if section not in data:
            continue
        for pkg_name, info in data[section].items():
            normalized = pkg_name.lower().replace("-", "_")
            if normalized in ALL_PACKAGES or pkg_name.lower() in ALL_PACKAGES:
                ver = info.get("version", "").lstrip("=")
                results.append((normalized, ver if ver else None))
    return results


def parse_poetry_lock(content):
    """Parse poetry.lock (TOML format, regex-based)."""
    results = []
    # Split into [[package]] blocks
    blocks = re.split(r"\[\[package\]\]", content)
    for block in blocks:
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m:
            pkg = name_m.group(1).lower().replace("-", "_")
            if pkg in ALL_PACKAGES:
                ver = ver_m.group(1) if ver_m else None
                results.append((pkg, ver))
    return results


def parse_setup_py(content):
    """Parse setup.py for install_requires."""
    results = []
    # Find install_requires list
    m = re.search(r"install_requires\s*=\s*\[([^\]]*)\]", content, re.DOTALL)
    if m:
        requires_str = m.group(1)
        for pkg in ALL_PACKAGES:
            pkg_m = re.search(
                rf'["\']({re.escape(pkg)})\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?["\']',
                requires_str, re.IGNORECASE,
            )
            if pkg_m:
                ver = pkg_m.group(2)
                results.append((pkg, ver))
    return results


def parse_setup_cfg(content):
    """Parse setup.cfg for install_requires."""
    results = []
    in_install = False
    for line in content.splitlines():
        if line.strip() == "install_requires =":
            in_install = True
            continue
        if in_install:
            if line and not line[0].isspace():
                break
            stripped = line.strip()
            m = re.match(r"([a-zA-Z0-9_-]+)\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?", stripped)
            if m:
                pkg = m.group(1).lower().replace("-", "_")
                if pkg in ALL_PACKAGES:
                    results.append((pkg, m.group(2)))
    return results


def parse_dockerfile(content):
    """Parse Dockerfile for pip install commands."""
    results = []
    for line in content.splitlines():
        if "pip install" not in line.lower():
            continue
        for pkg in ALL_PACKAGES:
            m = re.search(
                rf"({re.escape(pkg)})\s*(?:[=~!<>]=?\s*([0-9][0-9a-zA-Z._-]*))?",
                line, re.IGNORECASE,
            )
            if m:
                results.append((pkg, m.group(2)))
    return results


# Map file patterns to parsers
PARSERS = {
    "requirements": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile.lock": parse_pipfile_lock,
    "Pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "setup.py": parse_setup_py,
    "setup.cfg": parse_setup_cfg,
    "Dockerfile": parse_dockerfile,
}


def get_parser(file_path):
    """Get the appropriate parser for a file path."""
    basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    if basename == "Pipfile.lock":
        return PARSERS["Pipfile.lock"]
    if basename == "Pipfile":
        return PARSERS["Pipfile"]
    if "requirements" in basename.lower() and basename.endswith(".txt"):
        return PARSERS["requirements"]
    if basename == "pyproject.toml":
        return PARSERS["pyproject.toml"]
    if basename == "poetry.lock":
        return PARSERS["poetry.lock"]
    if basename == "setup.py":
        return PARSERS["setup.py"]
    if basename == "setup.cfg":
        return PARSERS["setup.cfg"]
    if "Dockerfile" in basename or "dockerfile" in basename:
        return PARSERS["Dockerfile"]
    return None


def judge(package_name, version):
    """Judge the vulnerability status.

    Returns:
        (verdict, note) tuple.
    """
    normalized = package_name.lower().replace("-", "_")

    if normalized in INDIRECT_PACKAGES:
        return CHECK_INDIRECT, "litellmを間接依存として利用するパッケージ"

    # Direct litellm
    if version and version in VULNERABLE_VERSIONS:
        return VULNERABLE, f"脆弱バージョン {version} を使用"
    if version:
        return SAFE, f"バージョン {version} は安全"
    return WARNING, "バージョン未指定（脆弱バージョンがインストールされた可能性あり）"
