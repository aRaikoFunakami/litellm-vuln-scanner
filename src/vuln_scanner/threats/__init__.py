"""Threat registry and aggregate dispatch functions.

Threats are loaded from ``threats.json`` and instantiated as
``DataDrivenThreat`` objects backed by ecosystem-specific modules.
"""

from __future__ import annotations

import json
import os
from typing import Callable, List, Optional, Set, Tuple

from vuln_scanner.threats.base import (  # noqa: F401 – re-export
    VULNERABLE,
    SAFE,
    WARNING,
    CHECK_INDIRECT,
    ThreatDefinition,
)

# ── Registry ────────────────────────────────────────────────────────────────

_THREATS: List[ThreatDefinition] = []


def register(threat: ThreatDefinition) -> None:
    """Register a threat definition."""
    _THREATS.append(threat)


def get_all_threats() -> List[ThreatDefinition]:
    """Return all registered threat definitions."""
    return list(_THREATS)


# ── Aggregate helpers ───────────────────────────────────────────────────────

def get_all_packages() -> Set[str]:
    """Return the union of ``all_packages`` across every registered threat."""
    result: Set[str] = set()
    for t in _THREATS:
        result |= t.all_packages
    return result


def get_all_file_patterns_regex():
    """Aggregate compiled regex patterns from all threats (for GitHub client)."""
    patterns = []
    for t in _THREATS:
        patterns.extend(t.get_file_patterns_regex())
    return patterns


def get_all_file_patterns_glob() -> List[str]:
    """Aggregate glob patterns from all threats (for local scanner)."""
    seen: Set[str] = set()
    unique: List[str] = []
    for t in _THREATS:
        for p in t.get_file_patterns_glob():
            if p not in seen:
                seen.add(p)
                unique.append(p)
    return unique


# ── Aggregate dispatch ──────────────────────────────────────────────────────

def get_parser(file_path: str) -> Optional[Callable]:
    """Return a parser for *file_path* by consulting every registered threat.

    If multiple threats can parse the same file, a composite parser that
    merges results from all matching parsers is returned.
    """
    basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    parsers = []
    for t in _THREATS:
        p = t.match_file(basename)
        if p is not None:
            parsers.append(p)
    if not parsers:
        return None
    if len(parsers) == 1:
        return parsers[0]

    # Composite parser – merge results, deduplicate
    def _composite(content: str) -> List[Tuple[str, Optional[str]]]:
        results: List[Tuple[str, Optional[str]]] = []
        seen: set = set()
        for parser_fn in parsers:
            for item in parser_fn(content):
                if item not in seen:
                    seen.add(item)
                    results.append(item)
        return results

    return _composite


def judge(package_name: str, version: Optional[str]) -> Tuple[str, str]:
    """Delegate judgment to the threat that owns *package_name*."""
    normalized = package_name.lower().replace("-", "_")
    for t in _THREATS:
        owned = {p.lower().replace("-", "_") for p in t.all_packages}
        if normalized in owned:
            return t.judge(package_name, version)
    return SAFE, "対象外パッケージ"


# ── Auto-load threats from JSON ─────────────────────────────────────────────

from vuln_scanner.threats.data_driven import DataDrivenThreat  # noqa: E402
from vuln_scanner.threats.ecosystems import python as _py_eco  # noqa: E402
from vuln_scanner.threats.ecosystems import npm as _npm_eco  # noqa: E402

_ECOSYSTEM_MODULES = {
    "python": _py_eco,
    "npm": _npm_eco,
}

_DB_PATH = os.path.join(os.path.dirname(__file__), "threats.json")
with open(_DB_PATH, encoding="utf-8") as _f:
    _DB = json.load(_f)

for _entry in _DB:
    _eco_mod = _ECOSYSTEM_MODULES.get(_entry["ecosystem"])
    if _eco_mod is None:
        raise ValueError(
            f"Unknown ecosystem {_entry['ecosystem']!r} in threats.json "
            f"(threat: {_entry['name']!r}). "
            f"Available: {list(_ECOSYSTEM_MODULES)}"
        )
    register(DataDrivenThreat(_entry, _eco_mod))
