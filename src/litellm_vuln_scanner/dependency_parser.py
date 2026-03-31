"""Parse dependency files and detect supply chain attack vulnerabilities.

Supports:
- LiteLLM (Python/PyPI): v1.82.7, v1.82.8
- axios (npm): v1.14.1, v0.30.4 + plain-crypto-js
"""

import json
import re

# ── Verdict constants ──
VULNERABLE = "VULNERABLE"
SAFE = "SAFE"
WARNING = "WARNING"
CHECK_INDIRECT = "CHECK_INDIRECT"

# ── Threat: LiteLLM (Python/PyPI) ──
LITELLM_VULNERABLE_VERSIONS = {"1.82.7", "1.82.8"}
LITELLM_DIRECT_PACKAGE = "litellm"
LITELLM_INDIRECT_PACKAGES = {"openhands", "dspy", "agentops", "langfuse", "mlflow"}
LITELLM_ALL_PACKAGES = {LITELLM_DIRECT_PACKAGE} | LITELLM_INDIRECT_PACKAGES

# ── Threat: axios (npm) ──
AXIOS_VULNERABLE_VERSIONS = {"1.14.1", "0.30.4"}
AXIOS_DIRECT_PACKAGE = "axios"
AXIOS_MALICIOUS_PACKAGES = {"plain-crypto-js"}
AXIOS_ALL_PACKAGES = {AXIOS_DIRECT_PACKAGE} | AXIOS_MALICIOUS_PACKAGES

# Backward-compatible aliases (used by local_scanner, etc.)
VULNERABLE_VERSIONS = LITELLM_VULNERABLE_VERSIONS
DIRECT_PACKAGE = LITELLM_DIRECT_PACKAGE
INDIRECT_PACKAGES = LITELLM_INDIRECT_PACKAGES
ALL_PACKAGES = LITELLM_ALL_PACKAGES


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


# ── npm parsers ──

def _extract_semver(version_str):
    """Extract the semver portion from an npm version specifier.

    E.g. "^1.14.0" -> "1.14.0", "~0.30.4" -> "0.30.4", "1.14.1" -> "1.14.1"
    """
    if not version_str:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", version_str)
    return m.group(1) if m else None


def parse_package_json(content):
    """Parse package.json for axios and plain-crypto-js."""
    results = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return results
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg_name, ver_spec in deps.items():
            if pkg_name.lower() in AXIOS_ALL_PACKAGES:
                ver = _extract_semver(ver_spec) if isinstance(ver_spec, str) else None
                results.append((pkg_name.lower(), ver))
    return results


def parse_package_lock_json(content):
    """Parse package-lock.json (v2/v3 and v1 formats)."""
    results = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return results

    # v2/v3 format: "packages" key with "node_modules/..." keys
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            # key is "" (root) or "node_modules/axios" etc.
            pkg_name = key.rsplit("/", 1)[-1] if "/" in key else key
            if pkg_name.lower() in AXIOS_ALL_PACKAGES:
                ver = info.get("version")
                results.append((pkg_name.lower(), ver))

    # v1 format: "dependencies" key
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for pkg_name, info in deps.items():
            if pkg_name.lower() in AXIOS_ALL_PACKAGES:
                ver = info.get("version") if isinstance(info, dict) else None
                results.append((pkg_name.lower(), ver))
            # Check nested dependencies (transitive)
            if isinstance(info, dict) and "dependencies" in info:
                for sub_name, sub_info in info["dependencies"].items():
                    if sub_name.lower() in AXIOS_ALL_PACKAGES:
                        sub_ver = sub_info.get("version") if isinstance(sub_info, dict) else None
                        results.append((sub_name.lower(), sub_ver))

    # Deduplicate
    seen = set()
    unique = []
    for pkg, ver in results:
        key = (pkg, ver)
        if key not in seen:
            seen.add(key)
            unique.append((pkg, ver))
    return unique


def parse_yarn_lock(content):
    """Parse yarn.lock for axios and plain-crypto-js."""
    results = []
    current_pkg = None
    for line in content.splitlines():
        # yarn.lock entry header: "axios@^1.14.0:" or "axios@^1.14.0, axios@^1.0.0:"
        if not line.startswith(" ") and line.endswith(":"):
            header = line.rstrip(":")
            # Extract package names from header
            parts = [p.strip().strip('"') for p in header.split(",")]
            pkg_name = None
            for part in parts:
                # "axios@^1.14.0" -> "axios"
                at_idx = part.rfind("@")
                if at_idx > 0:
                    name = part[:at_idx]
                elif at_idx == 0:
                    # Scoped package like @scope/pkg
                    continue
                else:
                    name = part
                if name.lower() in AXIOS_ALL_PACKAGES:
                    pkg_name = name.lower()
                    break
            current_pkg = pkg_name
        elif current_pkg and line.strip().startswith("version"):
            m = re.match(r'\s+version\s+"?([^"]+)"?', line)
            if m:
                results.append((current_pkg, m.group(1)))
            current_pkg = None
    return results


def parse_pnpm_lock(content):
    """Parse pnpm-lock.yaml for axios and plain-crypto-js (simple regex)."""
    results = []
    # Match patterns like: /axios@1.14.1: or axios@1.14.1:
    for m in re.finditer(r"/?([a-zA-Z0-9_-]+)@(\d+\.\d+\.\d+[^:]*?):", content):
        pkg = m.group(1).lower()
        ver = m.group(2)
        if pkg in AXIOS_ALL_PACKAGES:
            results.append((pkg, ver))
    return results


# Map file patterns to parsers
PARSERS = {
    # Python ecosystem
    "requirements": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile.lock": parse_pipfile_lock,
    "Pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "setup.py": parse_setup_py,
    "setup.cfg": parse_setup_cfg,
    "Dockerfile": parse_dockerfile,
    # npm ecosystem
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
}


def get_parser(file_path):
    """Get the appropriate parser for a file path."""
    basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    # Python ecosystem
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
    # npm ecosystem
    if basename == "package-lock.json":
        return PARSERS["package-lock.json"]
    if basename == "package.json":
        return PARSERS["package.json"]
    if basename == "yarn.lock":
        return PARSERS["yarn.lock"]
    if basename == "pnpm-lock.yaml":
        return PARSERS["pnpm-lock.yaml"]
    return None


def judge(package_name, version):
    """Judge the vulnerability status for both Python and npm ecosystems.

    Returns:
        (verdict, note) tuple.
    """
    normalized = package_name.lower().replace("-", "_")

    # ── LiteLLM (Python) ──
    if normalized in LITELLM_INDIRECT_PACKAGES:
        return CHECK_INDIRECT, "litellmを間接依存として利用するパッケージ"
    if normalized == "litellm":
        if version and version in LITELLM_VULNERABLE_VERSIONS:
            return VULNERABLE, f"脆弱バージョン {version} を使用"
        if version:
            return SAFE, f"バージョン {version} は安全"
        return WARNING, "バージョン未指定（脆弱バージョンがインストールされた可能性あり）"

    # ── axios (npm) ──
    if normalized == "plain_crypto_js":
        return VULNERABLE, "悪意あるパッケージ plain-crypto-js を検出（axiosサプライチェーン攻撃）"
    if normalized == "axios":
        if version and version in AXIOS_VULNERABLE_VERSIONS:
            return VULNERABLE, f"脆弱バージョン {version} を使用（axiosサプライチェーン攻撃）"
        if version:
            return SAFE, f"バージョン {version} は安全"
        return WARNING, "バージョン未指定（脆弱バージョンがインストールされた可能性あり）"

    return SAFE, "対象外パッケージ"
