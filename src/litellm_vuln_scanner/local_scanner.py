"""Scan local directories for supply chain attack vulnerabilities.

Supports Python (litellm) and npm (axios) ecosystems.
"""

import glob
import os
import platform
import re
import shutil
import subprocess
import sys

from litellm_vuln_scanner.dependency_parser import (
    get_parser, judge,
    ALL_PACKAGES, DIRECT_PACKAGE, INDIRECT_PACKAGES,
    VULNERABLE, SAFE, WARNING, CHECK_INDIRECT, VULNERABLE_VERSIONS,
    AXIOS_ALL_PACKAGES, AXIOS_VULNERABLE_VERSIONS, AXIOS_MALICIOUS_PACKAGES,
)


def find_dependency_files(root_dir):
    """Find all dependency files under root_dir.

    Returns:
        List of absolute file paths.
    """
    patterns = [
        # Python ecosystem
        "**/requirements*.txt",
        "**/pyproject.toml",
        "**/Pipfile",
        "**/Pipfile.lock",
        "**/poetry.lock",
        "**/setup.py",
        "**/setup.cfg",
        "**/Dockerfile*",
        # npm ecosystem
        "**/package.json",
        "**/package-lock.json",
        "**/yarn.lock",
        "**/pnpm-lock.yaml",
    ]
    found = []
    for pattern in patterns:
        found.extend(glob.glob(os.path.join(root_dir, pattern), recursive=True))
    # Exclude files inside node_modules
    found = [f for f in found if "/node_modules/" not in f and "\\node_modules\\" not in f]
    # Deduplicate and sort
    return sorted(set(found))


def find_venvs(root_dir):
    """Find Python virtual environments under root_dir.

    Looks for common venv indicators: pyvenv.cfg, bin/activate or Scripts/activate.

    Returns:
        List of (venv_path, python_executable) tuples.
    """
    venvs = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip deep traversal into node_modules, .git, etc.
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "node_modules", "__pycache__", ".tox"}
        ]
        if "pyvenv.cfg" in filenames:
            # Find the python executable
            bin_dir = os.path.join(dirpath, "bin")
            scripts_dir = os.path.join(dirpath, "Scripts")  # Windows
            if os.path.isdir(bin_dir):
                python_path = os.path.join(bin_dir, "python")
                if os.path.isfile(python_path):
                    venvs.append((dirpath, python_path))
            elif os.path.isdir(scripts_dir):
                python_path = os.path.join(scripts_dir, "python.exe")
                if os.path.isfile(python_path):
                    venvs.append((dirpath, python_path))
            # Don't descend further into venv
            dirnames.clear()
    return venvs


def _parse_freeze_output(output):
    """Parse pip freeze / uv pip freeze output into {package: version} dict."""
    installed = {}
    for line in output.splitlines():
        line = line.strip()
        if "==" not in line:
            continue
        parts = line.split("==", 1)
        pkg = parts[0].lower().replace("-", "_")
        ver = parts[1]
        if pkg in ALL_PACKAGES:
            installed[pkg] = ver
    return installed


def check_installed_packages(python_executable=None, venv_path=None, logger=None):
    """Check installed litellm and related packages.

    Tries multiple methods in order:
    1. uv pip freeze --python {python} (if uv is available)
    2. python -m pip freeze
    3. Direct reading of site-packages (fallback)

    Args:
        python_executable: Path to python executable. None uses system python.
        venv_path: Path to virtual environment root (for uv pip freeze).
        logger: Optional logger.

    Returns:
        Dict of {package_name: version} for detected packages.
    """
    python = python_executable or sys.executable

    # Method 1: uv pip freeze (works even if pip is not installed in the venv)
    if shutil.which("uv"):
        uv_cmd = ["uv", "pip", "freeze", "--python", python]
        try:
            result = subprocess.run(uv_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                if logger:
                    logger.debug(f"    uv pip freeze 成功")
                return _parse_freeze_output(result.stdout)
            if logger:
                logger.debug(f"    uv pip freeze 失敗: {result.stderr.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Method 2: python -m pip freeze
    pip_cmd = [python, "-m", "pip", "freeze"]
    try:
        result = subprocess.run(pip_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            if logger:
                logger.debug(f"    pip freeze 成功")
            return _parse_freeze_output(result.stdout)
        if logger:
            logger.debug(f"    pip freeze 失敗: {result.stderr.strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        if logger:
            logger.debug(f"    pip freeze 失敗: {e}")

    # Method 3: Read .dist-info directories in site-packages
    search_root = venv_path or os.path.dirname(os.path.dirname(python))
    installed = _check_site_packages(search_root, logger)
    if installed:
        return installed

    return {}


def _check_site_packages(root, logger=None):
    """Scan site-packages directories for installed target packages."""
    installed = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        if not dirpath.endswith("site-packages"):
            continue
        if logger:
            logger.debug(f"    site-packages スキャン: {dirpath}")
        for entry in os.listdir(dirpath):
            if not entry.endswith(".dist-info"):
                continue
            # e.g. litellm-1.82.7.dist-info
            parts = entry[:-len(".dist-info")].rsplit("-", 1)
            if len(parts) != 2:
                continue
            pkg_name = parts[0].lower().replace("-", "_")
            pkg_ver = parts[1]
            if pkg_name in ALL_PACKAGES:
                installed[pkg_name] = pkg_ver
                if logger:
                    logger.debug(f"    dist-info 検出: {pkg_name}=={pkg_ver}")
        break  # Only check the first site-packages found at this level
    return installed


def find_plain_crypto_js(root_dir, logger=None):
    """Check for node_modules/plain-crypto-js directories under root_dir.

    Returns:
        List of absolute paths where plain-crypto-js was found.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", ".tox"}]
        if os.path.basename(dirpath) == "node_modules":
            malicious_dir = os.path.join(dirpath, "plain-crypto-js")
            if os.path.isdir(malicious_dir):
                found.append(malicious_dir)
                if logger:
                    logger.warning(f"    !! 悪意あるパッケージ検出: {malicious_dir}")
            # Don't recurse further into node_modules
            dirnames.clear()
    return found


def check_malware_artifacts(logger=None):
    """Check for known malware artifacts from the axios supply chain attack.

    Checks platform-specific paths reported by StepSecurity.
    Returns:
        List of dicts with artifact information.
    """
    artifacts = []
    system = platform.system()

    paths_to_check = []
    if system == "Darwin":
        paths_to_check.append("/Library/Caches/com.apple.act.mond")
    elif system == "Linux":
        paths_to_check.append("/tmp/ld.py")
    elif system == "Windows":
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        paths_to_check.append(os.path.join(program_data, "wt.exe"))

    for path in paths_to_check:
        if os.path.exists(path):
            artifacts.append({
                "path": path,
                "platform": system,
            })
            if logger:
                logger.warning(f"    !! マルウェア痕跡検出: {path}")
        else:
            if logger:
                logger.debug(f"    マルウェア痕跡なし: {path}")

    return artifacts


def _read_node_module_version(root_dir, pkg_name):
    """Read version from node_modules/{pkg}/package.json directly.

    Returns version string or None.
    """
    pkg_json_path = os.path.join(root_dir, "node_modules", pkg_name, "package.json")
    if not os.path.isfile(pkg_json_path):
        return None
    try:
        import json
        with open(pkg_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("version")
    except (OSError, ValueError):
        return None


def check_npm_packages(root_dir, logger=None):
    """Check installed axios/plain-crypto-js versions in an npm project.

    Tries multiple methods:
    1. npm list --json (requires node_modules)
    2. Direct reading of node_modules/{pkg}/package.json (fallback)

    Args:
        root_dir: Directory containing package.json.
        logger: Optional logger.

    Returns:
        Dict of {package_name: version} for detected packages, or empty dict.
    """
    # Only run if package.json exists at root
    if not os.path.isfile(os.path.join(root_dir, "package.json")):
        return {}

    # Check if node_modules exists at all
    node_modules_dir = os.path.join(root_dir, "node_modules")
    if not os.path.isdir(node_modules_dir):
        if logger:
            logger.debug(f"    node_modules なし: {root_dir} (skip npm installed check)")
        return {}

    installed = {}

    # Method 1: npm list --json
    if shutil.which("npm"):
        try:
            result = subprocess.run(
                ["npm", "list", "--json", "--depth=0"],
                capture_output=True, text=True, timeout=30, cwd=root_dir,
            )
            if result.returncode in (0, 1) and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                deps = data.get("dependencies", {})
                for pkg_name, info in deps.items():
                    if pkg_name.lower() in AXIOS_ALL_PACKAGES:
                        ver = info.get("version")
                        if ver:
                            installed[pkg_name.lower()] = ver
                            if logger:
                                logger.debug(f"    npm list 検出: {pkg_name}=={ver}")
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

    # Method 2: Direct read of node_modules/{pkg}/package.json (fallback)
    for pkg in AXIOS_ALL_PACKAGES:
        if pkg in installed:
            continue
        ver = _read_node_module_version(root_dir, pkg)
        if ver:
            installed[pkg] = ver
            if logger:
                logger.debug(f"    node_modules 直接読み取り: {pkg}=={ver}")

    return installed


def scan_local(root_dir, logger=None):
    """Scan a local directory for vulnerable dependencies.

    Returns:
        (findings, files_scanned, installed_info) tuple.
        installed_info is a list of dicts describing installed packages per environment.
    """
    findings = []
    root_dir = os.path.abspath(root_dir)

    # 0. List all subdirectories for audit trail
    subdirs = []
    try:
        subdirs = sorted([
            d for d in os.listdir(root_dir)
            if os.path.isdir(os.path.join(root_dir, d)) and not d.startswith(".")
        ])
    except OSError:
        pass
    if logger and subdirs:
        logger.info(f"  サブディレクトリ一覧 ({len(subdirs)}件): {subdirs}")

    # 1. Scan dependency files
    dep_files = find_dependency_files(root_dir)
    if logger:
        logger.info(f"  依存ファイル {len(dep_files)}件検出")
        for f in dep_files:
            logger.info(f"    - {os.path.relpath(f, root_dir)}")

        # Report directories with no dependency files
        if subdirs:
            dirs_with_deps = set()
            for f in dep_files:
                rel = os.path.relpath(f, root_dir)
                top_dir = rel.split(os.sep)[0]
                dirs_with_deps.add(top_dir)
            dirs_without = [d for d in subdirs if d not in dirs_with_deps]
            if dirs_without:
                logger.info(f"  依存ファイルなし ({len(dirs_without)}件): {dirs_without}")

    for file_path in dep_files:
        parser = get_parser(file_path)
        if not parser:
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        rel_path = os.path.relpath(file_path, root_dir)
        if logger:
            logger.debug(f"    {rel_path}: パース中 ({len(content)} bytes)")

        packages = parser(content)
        for pkg_name, version in packages:
            verdict, note = judge(pkg_name, version)
            findings.append({
                "repo": root_dir,
                "file_path": rel_path,
                "package": pkg_name,
                "version": version,
                "verdict": verdict,
                "note": note,
                "source": "dependency_file",
            })
            if logger:
                logger.debug(f"    検出: {pkg_name}=={version or '(未指定)'} → {verdict}")

    # 2. Check installed packages in system python
    installed_info = []
    if logger:
        logger.info(f"  システム Python のインストール済みパッケージを確認中...")
        logger.debug(f"    Python: {sys.executable}")

    system_installed = check_installed_packages(logger=logger)
    if system_installed:
        env_entry = {
            "environment": "system",
            "python": sys.executable,
            "packages": system_installed,
        }
        installed_info.append(env_entry)
        for pkg, ver in system_installed.items():
            verdict, note = judge(pkg, ver)
            # Override note for installed packages
            note = f"インストール済み (system python: {sys.executable})"
            findings.append({
                "repo": root_dir,
                "file_path": "(installed)",
                "package": pkg,
                "version": ver,
                "verdict": verdict,
                "note": note,
                "source": "pip_freeze",
            })
            if logger:
                logger.info(f"    インストール済み: {pkg}=={ver} → {verdict}")

    # 3. Check installed packages in virtual environments
    venvs = find_venvs(root_dir)
    if logger:
        logger.debug(f"  仮想環境 {len(venvs)}件検出")

    for venv_path, python_path in venvs:
        rel_venv = os.path.relpath(venv_path, root_dir)
        if logger:
            logger.info(f"  仮想環境を確認中: {rel_venv}")
            logger.debug(f"    Python: {python_path}")

        venv_installed = check_installed_packages(python_path, venv_path, logger)
        if venv_installed:
            env_entry = {
                "environment": rel_venv,
                "python": python_path,
                "packages": venv_installed,
            }
            installed_info.append(env_entry)
            for pkg, ver in venv_installed.items():
                verdict, note = judge(pkg, ver)
                note = f"インストール済み (venv: {rel_venv})"
                findings.append({
                    "repo": root_dir,
                    "file_path": f"(installed: {rel_venv})",
                    "package": pkg,
                    "version": ver,
                    "verdict": verdict,
                    "note": note,
                    "source": "pip_freeze",
                })
                if logger:
                    logger.info(f"    インストール済み: {pkg}=={ver} → {verdict}")

    # 4. Check for node_modules/plain-crypto-js (axios attack indicator)
    if logger:
        logger.info(f"  node_modules/plain-crypto-js を検索中...")
    malicious_dirs = find_plain_crypto_js(root_dir, logger)
    for malicious_dir in malicious_dirs:
        rel_path = os.path.relpath(malicious_dir, root_dir)
        findings.append({
            "repo": root_dir,
            "file_path": rel_path,
            "package": "plain-crypto-js",
            "version": None,
            "verdict": VULNERABLE,
            "note": "悪意あるパッケージ plain-crypto-js が node_modules に存在（axiosサプライチェーン攻撃）",
            "source": "node_modules",
        })

    # 5. Check for malware artifacts (axios attack)
    if logger:
        logger.info(f"  マルウェア痕跡を確認中...")
    artifacts = check_malware_artifacts(logger)
    for artifact in artifacts:
        findings.append({
            "repo": root_dir,
            "file_path": artifact["path"],
            "package": "(malware artifact)",
            "version": None,
            "verdict": VULNERABLE,
            "note": f"axiosサプライチェーン攻撃のマルウェア痕跡を検出 ({artifact['platform']})",
            "source": "malware_artifact",
        })

    # 6. Check npm installed packages in project directories
    npm_dirs = set()
    for f in dep_files:
        if os.path.basename(f) == "package.json":
            npm_dirs.add(os.path.dirname(f))
    for npm_dir in sorted(npm_dirs):
        rel_dir = os.path.relpath(npm_dir, root_dir)
        if logger:
            logger.info(f"  npm パッケージを確認中: {rel_dir}")
        npm_installed = check_npm_packages(npm_dir, logger)
        if npm_installed:
            env_entry = {
                "environment": f"npm:{rel_dir}",
                "python": "(npm)",
                "packages": npm_installed,
            }
            installed_info.append(env_entry)
            for pkg, ver in npm_installed.items():
                verdict, note = judge(pkg, ver)
                note = f"npm インストール済み (dir: {rel_dir})"
                findings.append({
                    "repo": root_dir,
                    "file_path": f"(npm installed: {rel_dir})",
                    "package": pkg,
                    "version": ver,
                    "verdict": verdict,
                    "note": note,
                    "source": "npm_list",
                })
                if logger:
                    logger.info(f"    npm インストール済み: {pkg}=={ver} → {verdict}")

    # 7. Enrich dependency_file findings with actual installed versions
    # Build a map of all installed packages across all environments
    all_installed_pkgs = {}  # {pkg_name: (version, env_label)}
    for env in installed_info:
        for pkg, ver in env["packages"].items():
            all_installed_pkgs[pkg] = (ver, env["environment"])

    # Also collect lockfile-resolved versions for npm packages, keyed by directory
    # (package-lock.json / yarn.lock give exact resolved versions)
    # lockfile_versions: {directory: {pkg_name: (version, lockfile_relpath)}}
    lockfile_versions = {}
    for f in dep_files:
        basename = os.path.basename(f)
        if basename not in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            continue
        parser = get_parser(f)
        if not parser:
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        lock_dir = os.path.dirname(f)
        if lock_dir not in lockfile_versions:
            lockfile_versions[lock_dir] = {}
        for pkg_name, ver in parser(content):
            if ver and pkg_name not in lockfile_versions[lock_dir]:
                lockfile_versions[lock_dir][pkg_name] = (ver, os.path.relpath(f, root_dir))

    for finding in findings:
        if finding["source"] != "dependency_file":
            continue
        pkg = finding["package"]

        # Prefer lockfile version for npm packages — same directory only
        file_basename = os.path.basename(finding["file_path"])
        if file_basename == "package.json":
            finding_abs = os.path.join(root_dir, finding["file_path"])
            finding_dir = os.path.dirname(finding_abs)
            dir_locks = lockfile_versions.get(finding_dir, {})
            if pkg in dir_locks:
                lock_ver, lock_file = dir_locks[pkg]
                finding["version"] = lock_ver
                verdict, _ = judge(pkg, lock_ver)
                finding["verdict"] = verdict
                finding["note"] = f"lockfile ({lock_file}) による実バージョン: {lock_ver}"
                if logger:
                    logger.info(f"    lockfile 補完: {pkg} → {lock_ver} ({lock_file}) → {verdict}")
                continue

            # Enrich with npm installed version from node_modules
            npm_env_key = f"npm:{os.path.relpath(finding_dir, root_dir)}"
            for env in installed_info:
                if env["environment"] == npm_env_key:
                    npm_pkgs = env["packages"]
                    if pkg in npm_pkgs:
                        actual_ver = npm_pkgs[pkg]
                        finding["version"] = actual_ver
                        verdict, _ = judge(pkg, actual_ver)
                        finding["verdict"] = verdict
                        finding["note"] = f"node_modules の実バージョン: {actual_ver} ({npm_env_key})"
                        if logger:
                            logger.info(f"    npm バージョン補完: {pkg} → {actual_ver} ({npm_env_key}) → {verdict}")
                    break
            continue

        # Python: enrich with pip freeze version
        if pkg in all_installed_pkgs:
            actual_ver, env_label = all_installed_pkgs[pkg]
            if not finding["version"]:
                finding["version"] = actual_ver
                verdict, _ = judge(pkg, actual_ver)
                finding["verdict"] = verdict
                finding["note"] = f"バージョン未指定だが実環境では {actual_ver} がインストール済み ({env_label})"
                if logger:
                    logger.info(f"    バージョン補完: {pkg} → {actual_ver} ({env_label}) → {verdict}")

    return findings, len(dep_files), installed_info
