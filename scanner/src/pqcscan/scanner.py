"""Walk a source tree, apply the rules and build a cryptographic inventory with migration priorities."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from .rules import CLASSICAL_WEAK, EXTENSIONS, KEY_ESTABLISHMENT, PQC, PROTOCOL, RULES, SIGNATURE, Rule

SKIP_DIRS = {".git", "node_modules", "bin", "obj", ".venv", "venv", "__pycache__", "dist", "build", ".terraform"}
SUPPRESS = "pqcscan:ignore"
MAX_FILE_BYTES = 2_000_000

# NIST IR 8547 (final, Oct 2026): quantum-vulnerable public-key algorithms deprecated after 2030,
# disallowed after 2035.
DEPRECATED_AFTER = 2030
DISALLOWED_AFTER = 2035


@dataclass
class Finding:
    rule: str
    algorithm: str
    category: str
    file: str
    line: int
    snippet: str
    replacement: str
    priority: str = "info"


@dataclass
class Settings:
    data_shelf_life_years: int = 10  # how long data encrypted today must stay confidential (Mosca's "x")
    migration_years: int = 3  # how long the migration of this system will take (Mosca's "y")
    exclude: list[str] = field(default_factory=list)
    today: date = field(default_factory=date.today)


def _kind(path: Path) -> str | None:
    if path.name.startswith(".env"):
        return "config"
    return EXTENSIONS.get(path.suffix.lower())


def _applies(rule: Rule, kind: str) -> bool:
    if not rule.languages:
        return True
    return kind in rule.languages


def priority(category: str, s: Settings) -> str:
    """Rank a finding.

    Key establishment is exposed to harvest-now-decrypt-later: if data must stay secret beyond the
    point a quantum attacker could exist, today's traffic is already at risk (Mosca: x + y > z).
    We take z as the years left until quantum-vulnerable algorithms are disallowed (2035), which
    is a planning horizon, not a prediction of when a quantum computer will exist.
    """
    if category == PQC:
        return "info"
    if category == CLASSICAL_WEAK:
        return "medium"
    years_left = max(0, DISALLOWED_AFTER - s.today.year)
    if category in (KEY_ESTABLISHMENT, PROTOCOL):
        return "critical" if s.data_shelf_life_years + s.migration_years > years_left else "high"
    if category == SIGNATURE:
        years_to_deprecation = max(0, DEPRECATED_AFTER - s.today.year)
        return "high" if s.migration_years >= years_to_deprecation else "medium"
    return "low"


def scan_text(text: str, rel: str, kind: str, s: Settings) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    for rule in RULES:
        if not _applies(rule, kind):
            continue
        for m in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            if SUPPRESS in line:
                continue
            out.append(
                Finding(
                    rule=rule.id,
                    algorithm=rule.algorithm,
                    category=rule.category,
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:160],
                    replacement=rule.replacement,
                    priority=priority(rule.category, s),
                )
            )
    # One finding per rule per line is enough for an inventory.
    seen, unique = set(), []
    for f in out:
        key = (f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_path(root: str | Path, s: Settings | None = None) -> list[Finding]:
    s = s or Settings()
    root = Path(root)
    findings: list[Finding] = []
    files = [root] if root.is_file() else _walk(root, s)
    for path in files:
        kind = _kind(path)
        if kind is None or path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        findings += scan_text(text, rel, kind, s)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (order[f.priority], f.file, f.line, f.rule))


def _walk(root: Path, s: Settings) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pat) for pat in s.exclude):
                continue
            out.append(p)
    return out


def summarise(findings: list[Finding]) -> dict:
    by_priority: dict[str, int] = {}
    by_algorithm: dict[str, int] = {}
    for f in findings:
        by_priority[f.priority] = by_priority.get(f.priority, 0) + 1
        by_algorithm[f.algorithm] = by_algorithm.get(f.algorithm, 0) + 1
    vulnerable = [f for f in findings if f.category in (KEY_ESTABLISHMENT, SIGNATURE, PROTOCOL)]
    pqc = [f for f in findings if f.category == PQC]
    return {
        "total": len(findings),
        "quantum_vulnerable": len(vulnerable),
        "post_quantum_in_use": len(pqc),
        "files_affected": len({f.file for f in vulnerable}),
        "by_priority": dict(sorted(by_priority.items())),
        "by_algorithm": dict(sorted(by_algorithm.items())),
    }


def as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
