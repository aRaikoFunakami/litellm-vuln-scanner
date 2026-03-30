"""Scan local directories for litellm dependencies and installed packages."""

import glob
import os
import re
import subprocess
import sys

from litellm_vuln_scanner.dependency_parser import (
    get_parser, judge, ALL_PACKAGES, DIRECT_PACKAGE, INDIRECT_PACKAGES,
    VULNERABLE, SAFE, WARNING, CHECK_INDIRECT, VULNERABLE_VERSIONS,
)


def find_dependency_files(root_dir):
    """Find all dependency files under root_dir.

    Returns:
        List of absolute file paths.
    """
    patterns = [
        "**/requirements*.txt",
        "**/pyproject.toml",
        "**/Pipfile",
        "**/Pipfile.lock",
        "**/poetry.lock",
        "**/setup.py",
        "**/setup.cfg",
        "**/Dockerfile*",
    ]
    found = []
    for pattern in patterns:
        found.extend(glob.glob(os.path.join(root_dir, pattern), recursive=True))
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


def check_installed_packages(python_executable=None, logger=None):
    """Check installed litellm and related packages using pip freeze.

    Args:
        python_executable: Path to python executable. None uses system python.
        logger: Optional logger.

    Returns:
        Dict of {package_name: version} for detected packages.
    """
    cmd = [python_executable or sys.executable, "-m", "pip", "freeze"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        if logger:
            logger.debug(f"  pip freeze 失敗: {e}")
        return {}

    if result.returncode != 0:
        if logger:
            logger.debug(f"  pip freeze エラー: {result.stderr.strip()}")
        return {}

    installed = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if "==" not in line:
            continue
        parts = line.split("==", 1)
        pkg = parts[0].lower().replace("-", "_")
        ver = parts[1]
        if pkg in ALL_PACKAGES:
            installed[pkg] = ver
    return installed


def scan_local(root_dir, logger=None):
    """Scan a local directory for vulnerable dependencies.

    Returns:
        (findings, files_scanned, installed_info) tuple.
        installed_info is a list of dicts describing installed packages per environment.
    """
    findings = []
    root_dir = os.path.abspath(root_dir)

    # 1. Scan dependency files
    dep_files = find_dependency_files(root_dir)
    if logger:
        logger.debug(f"  依存ファイル {len(dep_files)}件検出")

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

    system_installed = check_installed_packages(None, logger)
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

        venv_installed = check_installed_packages(python_path, logger)
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

    return findings, len(dep_files), installed_info
